# Unit tests for format_check.py: python -m unittest discover -s .github/scripts -p "test_format_check.py"

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import format_check as fc  # noqa: E402


def toks(src):
    return fc.tokenize(src.encode('latin-1')).toks


class TokenizerTest(unittest.TestCase):

    def test_braces_and_comment_markers_inside_string(self):
        self.assertEqual(toks('s = "{ /* } // \\" {";'),
                         ['s', '=', '"{ /* } // \\" {"', ';'])

    def test_char_literals(self):
        self.assertEqual(toks("c = '{'; d = '}'; e = '\\''; f = '\"'; g = '/';"),
                         ['c', '=', "'{'", ';', 'd', '=', "'}'", ';', 'e', '=', "'\\''", ';',
                          'f', '=', "'\"'", ';', 'g', '=', "'/'", ';'])

    def test_comments_are_dropped(self):
        self.assertEqual(toks('a /* { } */ b // } {\nc'), ['a', 'b', 'c'])
        self.assertEqual(toks('a/**/b'), ['a', 'b'])
        self.assertEqual(toks('x = a /*\n multi\n line */ + b;'), ['x', '=', 'a', '+', 'b', ';'])

    def test_comment_marker_needs_both_characters(self):
        self.assertEqual(toks('x = a / *p;'), ['x', '=', 'a', '/', '*', 'p', ';'])
        self.assertEqual(toks('x = a /*p;*/;'), ['x', '=', 'a', ';'])

    def test_line_continuation_in_macro(self):
        self.assertEqual(toks('#define X(a) \\\n\tdo { f(a); } \\\n\twhile (0)\nint y;'),
                         ['#', 'define', 'X', '<params(>', 'a', ')', 'do', '{', 'f', '(', 'a', ')', ';',
                          '}', 'while', '(', '0', ')', '<EOL>', 'int', 'y', ';'])

    def test_line_continuation_inside_token(self):
        self.assertEqual(toks('fo\\\no = 1\\\n2;'), ['foo', '=', '12', ';'])

    def test_line_continuation_extends_line_comment(self):
        self.assertEqual(toks('a; // comment \\\nb;\nc;'), ['a', ';', 'c', ';'])

    def test_crlf(self):
        self.assertEqual(toks('#define A 1 \\\r\n + 2\r\nint b;\r\n'),
                         ['#', 'define', 'A', '1', '+', '2', '<EOL>', 'int', 'b', ';'])

    def test_continuation_versus_reindent(self):
        a = '#define M(x)   \\\n    f(x);   \\\n    g(x)\n'
        b = '#define M(x) \\\n\tf(x); \\\n\tg(x)\n'
        self.assertEqual(toks(a), toks(b))

    def test_preprocessor_lines(self):
        self.assertEqual(toks('  #  if A\nx;\n#endif'),
                         ['#', 'if', 'A', '<EOL>', 'x', ';', '#', 'endif', '<EOL>'])
        self.assertEqual(toks('/* c */ #pragma once\n'), ['#', 'pragma', 'once', '<EOL>'])
        self.assertEqual(toks('a # b\n'), ['a', '#', 'b'])
        self.assertEqual(toks('#define S(x) #x\n#define C(a, b) a##b\n'),
                         ['#', 'define', 'S', '<params(>', 'x', ')', '#', 'x', '<EOL>',
                          '#', 'define', 'C', '<params(>', 'a', ',', 'b', ')', 'a', '##', 'b',
                          '<EOL>'])

    def test_function_like_versus_object_like_macro(self):
        self.assertNotEqual(toks('#define F(x) x\n'), toks('#define F (x) x\n'))
        self.assertEqual(toks('#define F(x) x\n'), toks('#  define   F(x)    x\n'))
        self.assertEqual(toks('#define V (1)\n'), ['#', 'define', 'V', '(', '1', ')', '<EOL>'])

    def test_directive_boundary_is_a_token(self):
        self.assertNotEqual(toks('#define A 1\n+ 2;'), toks('#define A 1 + 2;'))

    def test_header_names(self):
        self.assertEqual(toks('#include <a//b.h>\n#include "c.h"\n'),
                         ['#', 'include', '<a//b.h>', '<EOL>', '#', 'include', '"c.h"', '<EOL>'])

    def test_unterminated_quote_in_directive_stays_on_its_line(self):
        self.assertEqual(toks("#error don't\nint a;"),
                         ['#', 'error', 'don', "'t", '<EOL>', 'int', 'a', ';'])

    def test_literal_prefixes(self):
        self.assertEqual(toks('L"w" u8"x" U\'y\' Lx'), ['L"w"', 'u8"x"', "U'y'", 'Lx'])

    def test_raw_string(self):
        self.assertEqual(toks('s = R"x(a "} // )x";'), ['s', '=', 'R"x(a "} // )x"', ';'])

    def test_numbers(self):
        self.assertEqual(toks('0x1e+5 1.5e-3f .5 10ULL 0x7FFFFFFF'),
                         ['0x1e+5', '1.5e-3f', '.5', '10ULL', '0x7FFFFFFF'])

    def test_operators_maximal_munch(self):
        self.assertEqual(toks('a--b'), ['a', '--', 'b'])
        self.assertEqual(toks('a - -b'), ['a', '-', '-', 'b'])
        self.assertNotEqual(toks('a - -b'), toks('a--b'))
        self.assertEqual(toks('x >>= 1; p->q; ...'), ['x', '>>=', '1', ';', 'p', '->', 'q', ';', '...'])

    def test_bom(self):
        self.assertEqual(fc.tokenize(b'\xef\xbb\xbfint a;').toks, ['<BOM>', 'int', 'a', ';'])
        self.assertNotEqual(fc.tokenize(b'\xef\xbb\xbfint a;').toks, fc.tokenize(b'int a;').toks)

    def test_non_ascii_bytes_round_trip(self):
        self.assertEqual(fc.tokenize('s = "あ";'.encode('utf-8')).toks[2],
                         '"あ"'.encode('utf-8').decode('latin-1'))

    def test_layout_change_is_identical(self):
        allman = ('void f(int a)\n{\n\tif (a)\n\t{\n\t\tg();\n\t}\n\telse\n\t{\n\t\th();\n\t}\n'
                  '\tfor (i = 0;i < 3;i++)\n\t{\n\t\tk();\n\t}\n}\n')
        attach = ('void f(int a) {\n\tif (a) {\n\t\tg();\n\t} else {\n\t\th();\n\t}\n'
                  '\tfor (i = 0; i < 3; i++) {\n\t\tk();\n\t}\n}\n')
        self.assertEqual(toks(allman), toks(attach))

    def test_line_numbers(self):
        t = fc.tokenize(b'a\nb \\\nc\nd')
        self.assertEqual(t.toks, ['a', 'b', 'c', 'd'])
        self.assertEqual(t.lines, [1, 2, 3, 4])


class BracesTest(unittest.TestCase):

    def check(self, before, after, macros=frozenset()):
        return fc.check_braces(toks(before), toks(after), set(macros))

    def ok(self, before, after, pairs, macros=frozenset()):
        removed, err = self.check(before, after, macros)
        self.assertIsNone(err)
        self.assertEqual(removed, pairs)

    def bad(self, before, after, macros=frozenset()):
        removed, err = self.check(before, after, macros)
        self.assertIsNotNone(err)
        return err[2]

    def test_simple(self):
        self.ok('if (a) { return; }', 'if (a) return;', 1)
        self.ok('if (a) { x(); } else { y(); }', 'if (a) x(); else y();', 2)
        self.ok('while (a) { a--; }', 'while (a) a--;', 1)
        self.ok('for (;;) { f(); }', 'for (;;) f();', 1)
        self.ok('do { f(); } while (a);', 'do f(); while (a);', 1)
        self.ok('if (a) { x(); } else if (b) { y(); }', 'if (a) x(); else if (b) y();', 2)

    def test_no_change(self):
        self.ok('if (a) { x(); y(); }', 'if (a) { x(); y(); }', 0)

    def test_nested(self):
        self.ok('if (a) { if (b) { x(); } else { y(); } }', 'if (a) if (b) x(); else y();', 3)
        self.ok('for (;;) { if (b) { x(); } }', 'for (;;) if (b) x();', 2)

    def test_two_statements(self):
        self.assertIn('exactly one statement', self.bad('if (a) { x(); y(); }', 'if (a) x(); y();'))

    def test_dangling_else(self):
        self.assertIn('else', self.bad('if (a) { if (b) x(); } else y();',
                                       'if (a) if (b) x(); else y();'))
        self.assertIn('else', self.bad('if (p) { while (q) { if (b) x(); } } else w();',
                                       'if (p) while (q) if (b) x(); else w();'))
        self.ok('if (p) { while (q) { if (b) x(); } } else w();',
                'if (p) { while (q) if (b) x(); } else w();', 1)

    def test_position(self):
        self.assertIn('body', self.bad('int a[] = { 1 };', 'int a[] = 1 ;'))
        self.assertIn('body', self.bad('void f(void) { g(); }', 'void f(void) g();'))
        self.assertIn('body', self.bad('switch (a) { f(); }', 'switch (a) f();'))
        self.assertIn('body', self.bad('{ f(); }', 'f();'))

    def test_preprocessor_inside(self):
        self.bad('if (a) {\n#ifdef X\nf();\n#endif\n}', 'if (a)\n#ifdef X\nf();\n#endif\n')

    def test_labels_and_cases(self):
        self.bad('if (a) { l: f(); }', 'if (a) l: f();')
        self.bad('while (a) { case 1: f(); }', 'while (a) case 1: f();')

    def test_multi_statement_macro(self):
        macros = fc.unsafe_macros([toks('#define TWO a(); b()\n#define ONE(x) f(x)\n'
                                        '#define CHK(x) if (!(x)) return\n'
                                        '#define WRAP(x) do { a(); b(x); } while (0)\n'
                                        '#define LOOP for (;;)\n')])
        self.assertEqual(macros, {'TWO', 'CHK'})
        self.assertIn('macro', self.bad('if (a) { TWO; }', 'if (a) TWO;', macros))
        self.assertIn('macro', self.bad('if (a) { CHK(x); } else y();', 'if (a) CHK(x); else y();', macros))
        self.ok('if (a) { ONE(1); }', 'if (a) ONE(1);', 1, macros)
        self.ok('if (a) { WRAP(1); }', 'if (a) WRAP(1);', 1, macros)

    def test_other_changes_rejected(self):
        self.bad('if (a) { x(); }', 'if (a) y();')
        self.bad('if (a) { x(); }', 'if (a) { x(); } ;')
        self.bad('if (a) { x(); }', 'if (a) x()')
        self.bad('if (a) { x(); }', 'if (a) { x(); ')
        self.bad('x = (a);', 'x = a;')

    def test_unbalanced_deletion_rejected(self):
        # an unmatched '{' (for example one opened in both arms of an #if) cannot be deleted
        self.bad('if (a) { x();', 'if (a) x();')
        # deleting a '}' alone
        self.bad('if (a) { x(); }', 'if (a) { x();')

    def test_nested_pair_equivalence(self):
        self.ok('if (a) { { x(); } }', 'if (a) { x(); }', 1)

    def test_empty_body_rejected(self):
        self.bad('if (a) { }', 'if (a) ')

    def test_initializer_and_compound_literal_inside(self):
        self.ok('if (a) { p = (POINT){1, 2}; }', 'if (a) p = (POINT){1, 2};', 1)

    def test_declaration_text_is_one_statement(self):
        # A declaration as the only statement is a compile error in C once the braces go,
        # so the checker does not need to tell it from an expression.
        self.ok('if (a) { x = y; }', 'if (a) x = y;', 1)


if __name__ == '__main__':
    unittest.main()
