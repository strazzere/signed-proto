# signed-proto - Data Signing and Verification

This is a simple command-line tool written in Go that facilitates data signing and verification using RSA encryption. The tool leverages Protocol Buffers for message structure serialization. It accepts private and public key files, along with a file containing the data buffer to be signed or verified.

# Re-generating protobuf

```
protoc --go_out=lib/ proto/signed.proto
```

## Example command usage

```
go build cmd/sproto.go
./sproto -sign -privateKey <private_key_file> -buffer <raw_buffer_file>
./sproto -verify -publicKey <public_key_file> -buffer <signed_buffer_file>
```

# License

```
Copyright 2022-23 Tim 'diff' Strazzere <diff@protonmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```