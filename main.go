package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type alertManAlert struct {
	Annotations struct {
		Description string `json:"description"`
		Summary     string `json:"summary"`
	} `json:"annotations"`
	EndsAt       string            `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Labels       map[string]string `json:"labels"`
	StartsAt     string            `json:"startsAt"`
	Status       string            `json:"status"`
	Fingerprint  string            `json:"fingerprint"`
}

type alertManOut struct {
	Alerts            []alertManAlert `json:"alerts"`
	CommonAnnotations struct {
		Summary string `json:"summary"`
	} `json:"commonAnnotations"`
	CommonLabels struct {
		Severity  string `json:"severity"`
		Alertname string `json:"alertname"`
	} `json:"commonLabels"`
	ExternalURL string `json:"externalURL"`
	GroupKey    string `json:"groupKey"`
	GroupLabels struct {
		Alertname string `json:"alertname"`
	} `json:"groupLabels"`
	Receiver string `json:"receiver"`
	Status   string `json:"status"`
	Version  string `json:"version"`
}

type freshdeskOut struct {
	Subject       string `json:"subject"`
	Description   string `json:"description"`
	Status        int    `json:"status"`
	Priority      int    `json:"priority"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	Custom_Fields struct {
		Fingerprint string `json:"fingerprint"`
	} `json:"custom_fields"`
}

type freshdeskTicket struct {
	Subject     string                 `json:"subject"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Status      int                    `json:"status"`
	Priority    int                    `json:"priority"`
	Fields      []freshdeskTicketField `json:"fields"`
}

type freshdeskTicketField struct {
	Name string `json:"name"`
}

type freshServiceTicket struct {
	Tickets []struct {
		Subject         string        `json:"subject"`
		GroupID         interface{}   `json:"group_id"`
		DepartmentID    interface{}   `json:"department_id"`
		Category        string        `json:"category"`
		SubCategory     interface{}   `json:"sub_category"`
		ItemCategory    interface{}   `json:"item_category"`
		RequesterID     int64         `json:"requester_id"`
		ResponderID     interface{}   `json:"responder_id"`
		DueBy           time.Time     `json:"due_by"`
		FrEscalated     bool          `json:"fr_escalated"`
		Deleted         bool          `json:"deleted"`
		Spam            bool          `json:"spam"`
		EmailConfigID   interface{}   `json:"email_config_id"`
		FwdEmails       []interface{} `json:"fwd_emails"`
		ReplyCcEmails   []interface{} `json:"reply_cc_emails"`
		CcEmails        []interface{} `json:"cc_emails"`
		IsEscalated     bool          `json:"is_escalated"`
		FrDueBy         time.Time     `json:"fr_due_by"`
		ID              int           `json:"id"`
		Priority        int           `json:"priority"`
		Status          int           `json:"status"`
		Source          int           `json:"source"`
		CreatedAt       time.Time     `json:"created_at"`
		UpdatedAt       time.Time     `json:"updated_at"`
		ToEmails        interface{}   `json:"to_emails"`
		Type            string        `json:"type"`
		Description     string        `json:"description"`
		DescriptionText string        `json:"description_text"`
		CustomFields    struct {
		} `json:"custom_fields"`
	} `json:"tickets"`
}

const defaultListenAddress = "127.0.0.1:9095"

var (
	whURL          = flag.String("webhook.url", os.Getenv("FRESHDESK_API"), "Freshdesk API URL.")
	freshdeskToken = flag.String("freshdesk.token", os.Getenv("FRESHDESK_TOKEN"), "Freshdesk API Token")
	listenAddress  = flag.String("listen.address", os.Getenv("LISTEN_ADDRESS"), "Address:Port to listen on.")
)

func checkFdToken(freshdeskToken string) {
	if freshdeskToken == "" {
		log.Fatalf("Environment variable 'FRESHDESK_TOKEN' or CLI parameter 'freshdesk.token' not found.")
	}
}

func checkWhURL(whURL string) {
	if whURL == "" {
		log.Fatalf("Environment variable 'FRESHDESK_API' or CLI parameter 'webhook.url' not found.")
	}
	_, err := url.Parse(whURL)
	if err != nil {
		log.Fatalf("The Freshdesk API URL doesn't seem to be a valid URL.")
	}

	re := regexp.MustCompile(`^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)`)
	if ok := re.Match([]byte(whURL)); !ok {
		log.Printf("The Freshdesk API URL doesn't seem to be a valid URL.")
	}
}

func getTickets() {
	client := &http.Client{}
	url := *whURL

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(*freshdeskToken, "X")
	res, getErr := client.Do(req)
	if getErr != nil {
		log.Fatal(getErr)
	}
	if res.Body != nil {
		defer res.Body.Close()
	}
	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Fatal(readErr)
	}
	tickets := freshServiceTicket{}
	jsonErr := json.Unmarshal(body, &tickets)
	if jsonErr != nil {
		log.Fatal(jsonErr)
	}

}

func sendWebhook(amo *alertManOut) {

	// use enum iota to match incoming strings to int
	const (
		info     = iota + 1
		warning  = iota + 1
		error    = iota + 1
		critical = iota + 1
	)
	const (
		firing = iota + 2
		_
		_
		_
		resolved = iota + 1
	)

	groupedAlerts := make(map[string][]alertManAlert)
	client := &http.Client{}
	for _, alert := range amo.Alerts {
		groupedAlerts[alert.Status] = append(groupedAlerts[alert.Status], alert)

	}

	for status, alerts := range groupedAlerts {

		DO := freshdeskOut{
			Subject:     fmt.Sprintf("[%s:%d] %s", strings.ToUpper(status), len(alerts), amo.CommonLabels.Alertname),
			Description: amo.CommonAnnotations.Summary,
			Name:        amo.CommonLabels.Alertname,
			Email:       "phillip@kubermatic.com",
		}

		RichEmbed := freshdeskTicket{
			Subject:     fmt.Sprintf("[%s:%d] %s", strings.ToUpper(status), len(alerts), amo.CommonLabels.Alertname),
			Description: amo.CommonAnnotations.Summary,
		}
		if amo.CommonLabels.Severity == "warning" {
			DO.Priority = warning
		} else if amo.CommonLabels.Severity == "critical" {
			DO.Priority = critical
		}
		if amo.Status == "firing" {
			DO.Status = firing
		} else if amo.Status == "resolved" {
			DO.Status = resolved
		}

		if amo.CommonAnnotations.Summary != "" {
			DO.Subject = fmt.Sprintf(" === %s === \n", amo.CommonAnnotations.Summary)
		}

		for _, alert := range alerts {
			fingerprint := alert.Fingerprint

			DO.Custom_Fields.Fingerprint = fingerprint
			fmt.Println(fingerprint)
		}

		for _, alert := range alerts {
			realname := alert.Labels["instance"]
			if strings.Contains(realname, "localhost") && alert.Labels["exported_instance"] != "" {
				realname = alert.Labels["exported_instance"]
			}

			RichEmbed.Fields = append(RichEmbed.Fields, freshdeskTicketField{
				Name: fmt.Sprintf("[%s]: %s on %s", strings.ToUpper(status), alert.Labels["alertname"], realname),
			})
		}

		DOD, _ := json.Marshal(DO)

		// Create request
		req, _ := http.NewRequest("POST", *whURL, bytes.NewReader(DOD))
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth(*freshdeskToken, "X")
		// Fetch Request
		resp, _ := client.Do(req)
		defer resp.Body.Close()
		// Read Response Body
		respBody, _ := ioutil.ReadAll(resp.Body)

		fmt.Println("response Body : ", string(respBody))
	}
}

func main() {
	flag.Parse()
	checkWhURL(*whURL)
	checkFdToken(*freshdeskToken)
	getTickets(&freshServiceTicket)

	if *listenAddress == "" {
		*listenAddress = defaultListenAddress
	}

	log.Printf("Listening on: %s", *listenAddress)
	http.ListenAndServe(*listenAddress, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s - [%s] %s", r.Host, r.Method, r.URL.RawPath)

		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}

		amo := alertManOut{}
		err = json.Unmarshal(b, &amo)
		if err != nil {

			if len(b) > 1024 {
				log.Printf("Failed to unpack inbound alert request - %s...", string(b[:1023]))

			} else {
				log.Printf("Failed to unpack inbound alert request - %s", string(b))
			}

			return
		}
		sendWebhook(&amo)
	}))
}
