use super::*;

impl EbpfState {
    /// Poll for events from a probe's ring buffer
    ///
    /// Returns events emitted by the eBPF program via bpf-emit.
    /// The timeout specifies how long to wait for events.
    pub fn poll_events(&self, id: u32, _timeout: Duration) -> Result<Vec<BpfEvent>, LoadError> {
        let mut probes = self.probes.lock().map_err(|_| LoadError::LockPoisoned)?;
        let probe = probes.get_mut(&id).ok_or(LoadError::ProbeNotFound(id))?;

        if !probe.has_ringbuf {
            // No ring buffer, return empty
            return Ok(Vec::new());
        }

        let ringbuf = match &mut probe.ringbuf {
            Some(rb) => rb,
            None => return Ok(Vec::new()),
        };

        let mut events = Vec::new();

        // Clone the schema for use in parsing (to avoid borrow issues)
        let schema = probe.event_schema.clone();

        // Read events from ring buffer (non-blocking)
        // Ring buffer returns events one at a time via next()
        while let Some(item) = ringbuf.next() {
            let buf: &[u8] = &item;
            let data = if let Some(ref event_schema) = schema {
                // We have a schema - deserialize structured event
                Self::deserialize_structured_event(buf, event_schema)
            } else {
                // No schema - use legacy size-based detection
                Self::deserialize_simple_event(buf)
            };

            if let Some(data) = data {
                events.push(BpfEvent {
                    data,
                    cpu: 0, // Ring buffer doesn't provide CPU info directly
                });
            }
        }

        Ok(events)
    }

    /// Deserialize a simple (non-structured) event based on size
    pub(super) fn deserialize_simple_event(buf: &[u8]) -> Option<BpfEventData> {
        // Ring buffer events have exact sizes (no padding like perf buffer)
        // - 8 bytes: integer from emit
        // - 16+ bytes: string ($ctx.comm uses 16, read-str uses 128)
        if buf.len() == 8 {
            // 8 bytes = integer from emit
            let value = i64::from_le_bytes(buf[0..8].try_into().unwrap());
            Some(BpfEventData::Int(value))
        } else if buf.len() >= 16 {
            // 16+ bytes = string (from $ctx.comm | emit or read-str)
            // Find null terminator within the buffer
            let null_pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            let s = String::from_utf8_lossy(&buf[..null_pos]).to_string();
            Some(BpfEventData::String(s))
        } else if !buf.is_empty() {
            // Unknown size - return raw bytes
            Some(BpfEventData::Bytes(buf.to_vec()))
        } else {
            None
        }
    }

    /// Deserialize a structured event using the schema
    pub(super) fn deserialize_structured_event(
        buf: &[u8],
        schema: &EventSchema,
    ) -> Option<BpfEventData> {
        if buf.len() < schema.total_size {
            // Buffer too small for the expected schema
            return Self::deserialize_simple_event(buf);
        }

        let mut fields = Vec::with_capacity(schema.fields.len());

        for (idx, field) in schema.fields.iter().enumerate() {
            let next_offset = schema
                .fields
                .get(idx + 1)
                .map(|f| f.offset)
                .unwrap_or(schema.total_size);
            let field_size = next_offset.saturating_sub(field.offset);
            // Bounds check: ensure field.offset is within buffer
            if field.offset >= buf.len() {
                // Field offset out of bounds, skip this field
                continue;
            }
            let available = buf.len() - field.offset;
            let slice_len = field_size.min(available);
            let field_buf = &buf[field.offset..field.offset + slice_len];
            let value = match field.field_type {
                BpfFieldType::Int => {
                    if field_buf.len() >= 8 {
                        let val = i64::from_le_bytes(field_buf[0..8].try_into().unwrap());
                        BpfFieldValue::Int(val)
                    } else {
                        BpfFieldValue::Int(0)
                    }
                }
                BpfFieldType::Comm => {
                    // 16-byte comm string
                    let max_len = field_buf.len().min(16);
                    let null_pos = field_buf[..max_len]
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(max_len);
                    let s = String::from_utf8_lossy(&field_buf[..null_pos]).to_string();
                    BpfFieldValue::String(s)
                }
                BpfFieldType::String => {
                    // String size is derived from schema offsets
                    let max_len = field_buf.len();
                    let null_pos = field_buf[..max_len]
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(max_len);
                    let s = String::from_utf8_lossy(&field_buf[..null_pos]).to_string();
                    BpfFieldValue::String(s)
                }
            };
            fields.push((field.name.clone(), value));
        }

        Some(BpfEventData::Record(fields))
    }
}
