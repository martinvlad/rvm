//! `StreamSession` as a [`FrameTarget`], plain and witnessed, so the
//! descriptor-limited [`FrameReader`](rvm_rvf::stream::FrameReader) drives it.

use crate::stream_session::StreamSession;
use crate::stream_session_types::{SessionError, SessionEvent, SessionState};
use rvm_rvf::stream::witness::{binding_of, witness_transition};
use rvm_rvf::stream::{FrameTarget, StreamError, StreamState};
use rvm_rvf::WitnessContext;
use rvm_witness::WitnessLog;

impl FrameTarget for StreamSession<'_> {
    type Out<'a> = SessionEvent;
    type Error = SessionError;

    fn state(&self) -> StreamState {
        let s = self.admission.state();
        if self.state == SessionState::Failed && !s.is_terminal() {
            // A failed session accepts no more input; tell the reader so.
            return StreamState::Suspended;
        }
        s
    }

    fn frame_payload_limit(&self, frame_type: u8) -> u64 {
        self.admission.verifier().frame_payload_limit(frame_type)
    }

    fn poison(&mut self, reason: StreamError) -> StreamError {
        self.admission.verifier_poison(reason)
    }

    fn push_frame(&mut self, frame: &[u8]) -> Result<SessionEvent, SessionError> {
        self.push(frame)
    }
}

/// A session plus the log its reader-level poison is written to.
pub(crate) struct Witnessed<'s, 'p, 'l, const N: usize> {
    pub(crate) session: &'s mut StreamSession<'p>,
    pub(crate) log: &'l WitnessLog<N>,
    pub(crate) ctx: WitnessContext,
}

impl<const N: usize> FrameTarget for Witnessed<'_, '_, '_, N> {
    type Out<'a> = SessionEvent;
    type Error = SessionError;

    fn state(&self) -> StreamState {
        FrameTarget::state(&*self.session)
    }

    fn frame_payload_limit(&self, frame_type: u8) -> u64 {
        self.session.frame_payload_limit(frame_type)
    }

    fn poison(&mut self, reason: StreamError) -> StreamError {
        let was = self.session.admission.state();
        let e = self.session.admission.verifier_poison(reason);
        // Before any descriptor there is no binding: the record carries an
        // all-zero one, which marks the poison as unauthenticated.
        let b = binding_of(&self.session.admission).unwrap_or([0; 32]);
        witness_transition(&self.session.admission, was, &b, self.log, self.ctx);
        e
    }

    fn push_frame(&mut self, frame: &[u8]) -> Result<SessionEvent, SessionError> {
        self.session.push_witnessed(frame, self.log, self.ctx)
    }
}
