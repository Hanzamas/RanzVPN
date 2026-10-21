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
        # an else behind a directive line still binds to the inner if
        self.assertIn('else', self.bad('if (a) { if (b) x(); }\n#ifdef W\nelse y();\n#endif\n',
                                       'if (a) if (b) x();\n#ifdef W\nelse y();\n#endif\n'))
        self.ok('if (a) { if (b) x(); }\n#ifdef W\nz();\n#endif\n',
                'if (a) if (b) x();\n#ifdef W\nz();\n#endif\n', 1)

    def test_dangling_else_in_every_arm(self):
        # the else in the #else arm binds to 'if (b)' once the braces go, although the first
        # arm starts with x()
        before = 'if (a) {\n if (b) g();\n}\n#ifdef X\nx();\n#else\nelse y();\n#endif'
        after = 'if (a)\n if (b) g();\n\n#ifdef X\nx();\n#else\nelse y();\n#endif'
        self.assertIn('else', self.bad(before, after))
        # an #elif arm, and an arm of a nested group
        self.assertIn('else', self.bad(
            'if (a) { if (b) g(); }\n#if A\nx();\n#elif B\nelse y();\n#endif\n',
            'if (a) if (b) g();\n#if A\nx();\n#elif B\nelse y();\n#endif\n'))
        self.assertIn('else', self.bad(
            'if (a) { if (b) g(); }\n#ifdef X\nx();\n#else\n#ifdef Y\nelse y();\n#endif\n#endif\n',
            'if (a) if (b) g();\n#ifdef X\nx();\n#else\n#ifdef Y\nelse y();\n#endif\n#endif\n'))
        # empty arms lead to the token after the group
        self.assertIn('else', self.bad(
            'if (a) { if (b) g(); }\n#ifdef X\n#define Q 1\n#else\n#define Q 2\n#endif\nelse y();\n',
            'if (a) if (b) g();\n#ifdef X\n#define Q 1\n#else\n#define Q 2\n#endif\nelse y();\n'))
        self.assertIn('else', self.bad(
            'if (a) { if (b) g(); }\n#if A\nx();\n#elif B\n#endif\nelse y();\n',
            'if (a) if (b) g();\n#if A\nx();\n#elif B\n#endif\nelse y();\n'))
        # every arm starts with something else: fine
        self.ok('if (a) { if (b) g(); }\n#if A\nx();\n#elif B\nz();\n#else\nw();\n#endif\nelse y();\n',
                'if (a) if (b) g();\n#if A\nx();\n#elif B\nz();\n#else\nw();\n#endif\nelse y();\n', 1)

    def test_dangling_else_after_the_end_of_an_arm(self):
        # '}' then #else: the X arm goes on after the #endif, where the else is
        before = ('#ifdef X\nif (a) {\n if (b) g();\n}\n#else\nif (a) h();\n#endif\n'
                  'else y();\n')
        after = '#ifdef X\nif (a)\n if (b) g();\n#else\nif (a) h();\n#endif\nelse y();\n'
        self.assertIn('else', self.bad(before, after))
        # '}' then #endif
        before = 'if (a) x();\n#ifdef X\nelse if (c) {\n if (b) g();\n}\n#endif\nelse y();\n'
        after = 'if (a) x();\n#ifdef X\nelse if (c)\n if (b) g();\n#endif\nelse y();\n'
        self.assertIn('else', self.bad(before, after))
        # the #else arm is not a path from the end of the first arm
        self.ok('#ifdef X\nif (a) {\n if (b) g();\n}\n#else\nelse h();\n#endif\nz();\n',
                '#ifdef X\nif (a)\n if (b) g();\n#else\nelse h();\n#endif\nz();\n', 1)

    def test_following_tokens(self):
        v = toks('a;\n#if A\nb;\n#elif B\n#else\n#ifdef C\nc;\n#endif\n#endif\nd;\n')
        self.assertEqual(fc.following_tokens(v, v.index(';')), {'b', 'c', 'd'})
        v = toks('#ifdef X\na;\n#else\nb;\n#endif\nc;')
        self.assertEqual(fc.following_tokens(v, v.index(';')), {'c'})
        self.assertEqual(fc.following_tokens(toks('a;'), 1), {None})

    def test_position(self):
        self.assertIn('body', self.bad('int a[] = { 1 };', 'int a[] = 1 ;'))
        self.assertIn('body', self.bad('void f(void) { g(); }', 'void f(void) g();'))
        self.assertIn('body', self.bad('switch (a) { f(); }', 'switch (a) f();'))
        self.assertIn('body', self.bad('{ f(); }', 'f();'))

    def test_preprocessor_inside(self):
        self.bad('if (a) {\n#ifdef X\nf();\n#endif\n}', 'if (a)\n#ifdef X\nf();\n#endif\n')

    def test_else_if_merge_with_directive_in_nested_block(self):
        self.ok('if (a) { x(); } else {\n\tif (b) {\n#ifdef W\n\t\ty();\n#endif\n\t\tz();\n\t}\n}\n',
                'if (a) { x(); } else if (b) {\n#ifdef W\n\ty();\n#endif\n\tz();\n}\n', 1)

    def test_directive_arms_must_keep_brackets_balanced(self):
        before = ('if (a) { x(); } else {\n\tif (b) {\n#ifdef W\n\t\tx();\n\t} else {\n#endif\n'
                  '\t\ty();\n\t}\n}\n')
        after = ('if (a) { x(); } else if (b) {\n#ifdef W\n\tx();\n} else {\n#endif\n'
                 '\ty();\n}\n')
        self.assertIn('balanced', self.bad(before, after))
        # two statements in the full stream are rejected before that
        self.bad('if (a) { x(); } else {\n\tif (b) {\n#ifdef W\n\t}\n\tif (c) {\n#endif\n'
                 '\t\tz();\n\t}\n}\n',
                 'if (a) { x(); } else if (b) {\n#ifdef W\n}\nif (c) {\n#endif\n\tz();\n}\n')

    def test_directive_at_top_level_of_body(self):
        self.bad('if (a) {\n#ifdef W\n\tif (b) x();\n#endif\n}\n', 'if (a)\n#ifdef W\n\tif (b) x();\n#endif\n')

    def test_macro_inside_nested_block_is_harmless(self):
        macros = {'TWO'}
        self.ok('if (a) { x(); } else { if (b) { TWO; } else { y(); } }',
                'if (a) { x(); } else if (b) { TWO; } else { y(); }', 1, macros)
        self.assertIn('macro', self.bad('if (a) { if (b) TWO; }', 'if (a) if (b) TWO;', macros))

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

    def test_macro_using_a_multi_statement_macro(self):
        # TWO2 and IFB expand to TWO and IFB2, so they are multi-statement too; ONE2 uses TWO
        # inside parentheses only
        macros = fc.unsafe_macros([toks('#define TWO2 TWO\n#define TWO a(); b()\n'
                                        '#define IFB(x) IFB2(x)\n#define IFB2(x) if (x)\n'
                                        '#define ONE2 f(TWO)\n')])
        self.assertEqual(macros, {'TWO', 'TWO2', 'IFB', 'IFB2'})
        self.assertIn('macro', self.bad('if (a) { TWO2; }', 'if (a) TWO2;', macros))
        self.assertIn('macro', self.bad('if (a) { IFB(b) g(); } else y();',
                                        'if (a) IFB(b) g(); else y();', macros))

    def test_dangling_else_from_a_following_macro(self):
        # EL expands to 'else', which binds to 'if (b)' once the braces go
        for defs in ('#define EL else\n', '#define EL(s) else s\n',
                     '#define EL EL2\n#define EL2 else\n'):
            macros = fc.unsafe_macros([toks(defs)])
            self.assertIn('EL', macros)
            self.assertIn('else', self.bad(defs + 'if (a) { if (b) g(); } EL y();\n',
                                           defs + 'if (a) if (b) g(); EL y();\n', macros))
            self.assertIn('else', self.bad(
                defs + 'if (a) { if (b) g(); }\n#ifdef X\nx();\n#else\nEL y();\n#endif\n',
                defs + 'if (a) if (b) g();\n#ifdef X\nx();\n#else\nEL y();\n#endif\n', macros))
        # without an open 'if' inside, a following macro is harmless
        macros = fc.unsafe_macros([toks('#define EL else\n')])
        self.ok('if (a) { g(); } EL y();', 'if (a) g(); EL y();', 1, macros)

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

    def test_declaration_is_not_a_statement(self):
        # In C a declaration is not a statement: 'if (a) int x = g();' does not compile.
        for decl in ('int x = g();', 'UINT x = g();', 'UINT x;', 'UCHAR *p = NULL;',
                     'char **pp;', 'UINT a[4];', 'UINT x, y;', 'BOOL f(void);', 'const UINT x = 1;',
                     'static int n;', 'struct S s;', 'enum E e = E1;', 'UINT const *p;',
                     'typedef int T;', 'unsigned x = 0;'):
            self.assertIn('declaration', self.bad('if (a) { %s }' % decl, 'if (a) %s' % decl),
                          decl)
        self.assertIn('declaration', self.bad('for (;;) { int x = g(); }', 'for (;;) int x = g();'))
        self.assertIn('declaration', self.bad('if (a) { { UINT x; } }', 'if (a) UINT x;'))
        # declarations inside a nested { } that stays are fine
        self.ok('if (a) { if (b) { UINT x = g(); h(x); } }',
                'if (a) if (b) { UINT x = g(); h(x); }', 1)

    def test_expression_statements_are_not_declarations(self):
        self.ok('if (a) { x = y; }', 'if (a) x = y;', 1)
        self.ok('if (a) { return x; }', 'if (a) return x;', 1)
        self.ok('if (a) { return *p; }', 'if (a) return *p;', 1)
        self.ok('if (a) { goto out; }', 'if (a) goto out;', 1)
        self.ok('if (a) { *p = x; }', 'if (a) *p = x;', 1)
        self.ok('if (a) { x = a * b; }', 'if (a) x = a * b;', 1)
        self.ok('if (a) { ok && f(x); }', 'if (a) ok && f(x);', 1)
        self.ok('if (a) { (void)f(x); }', 'if (a) (void)f(x);', 1)
        self.ok('if (a) { p->x = sizeof(UINT); }', 'if (a) p->x = sizeof(UINT);', 1)
        self.ok('while (a) { i++; }', 'while (a) i++;', 1)

    def test_braces_in_directive_rejected(self):
        # The pair would have to hold at every use of the macro: after 'M(a) else w();' the else
        # binds to the inner if once the braces go.
        before = '#define M(x) if (x) { if (y) z(); }\nvoid f(void) { M(a) else w(); }\n'
        after = '#define M(x) if (x) if (y) z();\nvoid f(void) { M(a) else w(); }\n'
        self.assertIn('directive', self.bad(before, after))
        self.assertIn('directive', self.bad('#define N(x) while (x) { f(); }\n',
                                            '#define N(x) while (x) f();\n'))
        self.assertIn('directive', self.bad('#define D do { f(); } while (0)\n',
                                            '#define D do f(); while (0)\n'))
        # the same pair outside a directive is fine, and a directive after it does not matter
        self.ok('if (x) { f(); }\n#define M(x) if (x) { g(); }\n',
                'if (x) f();\n#define M(x) if (x) { g(); }\n', 1)


if __name__ == '__main__':
    unittest.main()
