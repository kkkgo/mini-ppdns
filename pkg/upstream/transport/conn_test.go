package transport

import (
	"testing"
)

// minimalQuery is the smallest valid DNS query wire format that
// addQueueC's extractQuestion will accept: 12-byte header + root QNAME
// (single 0 byte) + QTYPE A (0x0001) + QCLASS IN (0x0001).
var minimalQuery = []byte{
	0x00, 0x00, // ID
	0x01, 0x00, // flags: standard query, RD set
	0x00, 0x01, // QDCOUNT
	0x00, 0x00, // ANCOUNT
	0x00, 0x00, // NSCOUNT
	0x00, 0x00, // ARCOUNT
	0x00,       // QNAME = root
	0x00, 0x01, // QTYPE A
	0x00, 0x01, // QCLASS IN
}

func BenchmarkConn_QueueAllocations(b *testing.B) {
	// Initialize a mock TraditionalDnsConn with default parameters
	dc := &TraditionalDnsConn{}

	// We only benchmark the queue addition/removal overhead with locks
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			qid, _ := dc.addQueueC(minimalQuery)
			dc.pending.lookup(qid)
			dc.deleteQueueC(qid)
		}
	})
}
