package maxmind

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestFetchASNFromRIRURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.UserAgent(); got != geoIPHTTPUserAgent {
			t.Fatalf("unexpected User-Agent: %q", got)
		}
		_, _ = w.Write([]byte(
			"apnic|JP|asn|173|1|20020801|allocated\n" +
				"apnic|JP|asn|2497|2|20020405|allocated\n" +
				"apnic|AU|asn|1221|1|20020801|allocated\n" +
				"apnic|JP|ipv4|1.0.16.0|256|20110412|allocated\n",
		))
	}))
	defer server.Close()

	got, err := fetchASNFromRIRURL(server.URL, "APNIC", "JP")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"AS173", "AS2497", "AS2498"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected ASNs: got %v, want %v", got, want)
	}
}

func TestFetchASNFromRIRURLRejectsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer server.Close()

	if _, err := fetchASNFromRIRURL(server.URL, "APNIC", "JP"); err == nil {
		t.Fatal("expected an error for HTTP 429")
	}
}
