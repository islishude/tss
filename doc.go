// Package tss defines transport-neutral building blocks shared by the
// threshold-signature protocol packages in this module.
//
// The root package intentionally does not provide a network transport, durable
// storage, or secret-at-rest encryption. Callers are responsible for authenticated
// confidential delivery of envelopes that set ConfidentialRequired.
package tss
