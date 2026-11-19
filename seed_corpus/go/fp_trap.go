// EXPECTED_FINDINGS: []
// FP-trap: "MD5" only inside a string literal.
package main
var label = "MD5"
var tlsMention = "tls.VersionTLS12 is only mentioned here"
