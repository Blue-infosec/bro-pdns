package main

import (
	"encoding/json"
	"io"
	"log"
	"strings"
	"time"

	"github.com/JustinAzoff/flow-indexer/backend"
)

var MAX_SANE_VALUE_LEN = 1000

func stripDecimal(value string) string {
	if value == "-" {
		return "0"
	}
	idx := strings.Index(value, ".")
	if idx == -1 {
		return value
	}
	return value[:idx]
}

type DNSRecord struct {
	ts      float64
	query   string
	qtype   string
	answers []string
	ttls    []string
}

type uniqueTuple struct {
	query  string
	answer string
	qtype  string
}
type uniqueIndividual struct {
	value string
	which string // "Q" or "A"
}

type queryStat struct {
	count uint
	first float64
	last  float64
	ttl   string
}

type aggregationResult struct {
	Duration       time.Duration
	TotalRecords   uint
	SkippedRecords uint
	Tuples         []aggregatedTuple
	TuplesLen      int
	Individual     []aggregatedIndividual
	IndividualLen  int
}

type aggregatedTuple struct {
	uniqueTuple
	queryStat
}
type aggregatedIndividual struct {
	uniqueIndividual
	queryStat
}

type DNSAggregator struct {
	queries        map[uniqueTuple]*queryStat
	values         map[uniqueIndividual]*queryStat
	totalRecords   uint
	skippedRecords uint
	start          time.Time
}

func NewDNSAggregator() *DNSAggregator {
	queries := make(map[uniqueTuple]*queryStat)
	values := make(map[uniqueIndividual]*queryStat)
	return &DNSAggregator{
		queries: queries,
		values:  values,
		start:   time.Now(),
	}
}
func (d *DNSAggregator) SkipRecord() {
	d.skippedRecords++
}

func (d *DNSAggregator) AddRecord(r DNSRecord) {
	if len(r.query) > MAX_SANE_VALUE_LEN {
		log.Printf("Skipping record with insane query length: %#v\n", r)
		d.skippedRecords++
		return
	}
	d.totalRecords++
	query_value := uniqueIndividual{value: r.query, which: "Q"}

	arec := d.values[query_value]
	if arec == nil {
		arec = &queryStat{
			first: r.ts,
			last:  r.ts,
			count: 1,
		}
		d.values[query_value] = arec
	} else {
		arec.count++
		arec.last = r.ts
	}

	for idx, answer := range r.answers {
		if len(answer) > MAX_SANE_VALUE_LEN {
			log.Printf("Skipping record with insane answer length: %#v\n", r)
			d.skippedRecords++
			return
		}
		if answer == "-" {
			continue
		}
		ttl := stripDecimal(r.ttls[idx])
		uquery := uniqueTuple{
			query:  r.query,
			answer: answer,
			qtype:  r.qtype,
		}
		rec := d.queries[uquery]
		if rec == nil {
			rec = &queryStat{
				first: r.ts,
				last:  r.ts,
				ttl:   ttl,
				count: 1,
			}
			d.queries[uquery] = rec
		} else {
			rec.count++
			rec.last = r.ts
			rec.ttl = ttl
		}

		answer_value := uniqueIndividual{value: answer, which: "A"}
		arec := d.values[answer_value]
		if arec == nil {
			arec = &queryStat{
				first: r.ts,
				last:  r.ts,
				ttl:   ttl,
				count: 1,
			}
			d.values[answer_value] = arec
		} else {
			arec.count++
			arec.last = r.ts
			arec.ttl = ttl
		}
	}

}

func (d *DNSAggregator) GetResult() aggregationResult {
	var result aggregationResult
	for q, stat := range d.queries {
		agg := aggregatedTuple{
			uniqueTuple: q,
			queryStat:   *stat,
		}
		result.Tuples = append(result.Tuples, agg)
	}
	for value, stat := range d.values {
		agg := aggregatedIndividual{
			uniqueIndividual: value,
			queryStat:        *stat,
		}
		result.Individual = append(result.Individual, agg)
	}
	result.TotalRecords = d.totalRecords
	result.SkippedRecords = d.skippedRecords
	result.Duration = time.Since(d.start)
	result.TuplesLen = len(result.Tuples)
	result.IndividualLen = len(result.Individual)
	return result

}

func (d *DNSAggregator) Merge(other *DNSAggregator) {
	for q, stat := range other.queries {
		rec := d.queries[q]
		if rec == nil {
			d.queries[q] = stat
		} else {
			rec.count += stat.count
			if stat.first < rec.first {
				rec.first = stat.first
			}
			if stat.last > rec.last {
				rec.last = stat.last
			}
			rec.ttl = stat.ttl
		}
	}
	for q, stat := range other.values {
		rec := d.values[q]
		if rec == nil {
			d.values[q] = stat
		} else {
			rec.count += stat.count
			if stat.first < rec.first {
				rec.first = stat.first
			}
			if stat.last > rec.last {
				rec.last = stat.last
			}
			rec.ttl = stat.ttl
		}
	}
	return
}

func aggregate(aggregator *DNSAggregator, fn string) error {
	f, err := backend.OpenDecompress(fn)
	if err != nil {
		return err
	}
	defer f.Close()
	br, err := NewBroReader(f)
	if err != nil {
		return err
	}

	for {
		rec, err := br.Next()
		if err != nil {
			return err
		}
		if rec == nil {
			break
		}
		ts := rec.GetFloat("ts")
		query := rec.GetString("query")
		qtype_name := rec.GetString("qtype_name")
		answers := rec.GetStringList("answers")
		ttls := rec.GetStringList("TTLs")
		if rec.Error() != nil {
			if rec.IsMissingFieldError() {
				log.Printf("Skipping record with missing fields: %s", rec)
				aggregator.SkipRecord()
				continue
			} else {
				return rec.Error()
			}
		}
		dns_record := DNSRecord{
			ts:      ts,
			query:   query,
			qtype:   qtype_name,
			answers: answers,
			ttls:    ttls,
		}
		aggregator.AddRecord(dns_record)
	}

	return nil
}

func (ar *aggregationResult) ShallowCopy() aggregationResult {
	return aggregationResult{
		Duration:       ar.Duration,
		TotalRecords:   ar.TotalRecords,
		SkippedRecords: ar.SkippedRecords,
		TuplesLen:      ar.TuplesLen,
		IndividualLen:  ar.IndividualLen,
	}
}

type JSONTuple struct {
	Query  string `json:"query"`
	Type   string `json:"type"`
	Answer string `json:"answer"`
	TTL    string `json:"ttl"`
	Count  uint   `json:"count"`
	First  uint64 `json:"first"`
	Last   uint64 `json:"last"`
}

func (ar *aggregationResult) TupleJSONReader(reverseQuery bool) io.ReadCloser {
	pr, pw := io.Pipe()

	encoder := json.NewEncoder(pw)
	go func() {
		defer pw.Close()
		var q string
		for _, t := range ar.Tuples {
			if reverseQuery {
				q = Reverse(t.query)
			} else {
				q = t.query
			}
			v := JSONTuple{
				Query:  q,
				Type:   t.qtype,
				Answer: t.answer,
				TTL:    t.ttl,
				Count:  t.count,
				First:  uint64(t.first),
				Last:   uint64(t.last),
			}
			err := encoder.Encode(v)
			if err != nil {
				pr.CloseWithError(err)
				return
			}
		}
	}()
	return pr
}

type JSONIndividual struct {
	Value string `json:"value"`
	Which string `json:"which"`
	Count uint   `json:"count"`
	First uint64 `json:"first"`
	Last  uint64 `json:"last"`
}

func (ar *aggregationResult) IndividualJSONReader(reverseQuery bool) io.ReadCloser {
	pr, pw := io.Pipe()

	encoder := json.NewEncoder(pw)
	go func() {
		defer pw.Close()
		var q string
		for _, t := range ar.Individual {
			if t.which == "Q" && reverseQuery {
				q = Reverse(t.value)
			} else {
				q = t.value
			}
			v := JSONIndividual{
				Value: q,
				Which: t.which,
				Count: t.count,
				First: uint64(t.first),
				Last:  uint64(t.last),
			}
			err := encoder.Encode(v)
			if err != nil {
				pr.CloseWithError(err)
				return
			}
		}
	}()
	return pr
}
