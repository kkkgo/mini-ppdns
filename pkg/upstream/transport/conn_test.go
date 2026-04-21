package transport

import (
	"testing"
)

func BenchmarkConn_QueueAllocations(b *testing.B) {
	// Initialize a mock TraditionalDnsConn with default parameters
	dc := &TraditionalDnsConn{}

	// We only benchmark the queue addition/removal overhead with locks
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			qid, _ := dc.addQueueC()
			dc.getQueueC(qid)
			dc.deleteQueueC(qid)
		}
	})
}
