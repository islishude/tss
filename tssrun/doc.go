// Package tssrun defines the production integration contract for TSS protocol
// runs.
//
// The package intentionally stays transport- and database-neutral. It provides
// small interfaces for run intent acceptance, active session routing,
// unknown-session handling, and durable lifecycle boundaries. Protocol packages
// still own cryptographic state machines and canonical wire formats.
//
// Memory implementations in this package are reference and test helpers. They
// are not durable stores and must not be used as the production source of truth.
package tssrun
