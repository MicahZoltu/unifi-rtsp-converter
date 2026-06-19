//! RTSP server accept loop and per-session state. Implements the minimal
//! RTSP method set (OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN) and negotiates
//! TCP-interleaved and UDP RTP transports.
