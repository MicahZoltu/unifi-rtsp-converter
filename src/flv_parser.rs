//! FLV stream parser. Detects the uPFLV magic prefix, validates the FLV
//! header, and runs the tag-framing state machine that emits tag events.
