// Package controlpb is the Go side of the control protocol: the code that protoc-gen-go
// generates from proto/ranz/control/v1/control.proto, the schema that the C node generates its
// nanopb code from too. control.pb.go is generated: change the schema and run go generate with
// the protoc and protoc-gen-go versions that .github/workflows/ranz.yml pins; CI fails
// when the committed file differs from what they generate.
package controlpb

//go:generate protoc -I ../../../proto --go_out=../.. --go_opt=module=github.com/Hanzamas/RanzVPN/controller ranz/control/v1/control.proto
