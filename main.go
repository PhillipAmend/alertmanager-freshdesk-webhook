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
}

type alertManOut struct {
	Alerts            []alertManAlert `json:"alerts"`
	CommonAnnotations struct {
		Summary string `json:"summary"`
	} `json:"commonAnnotations"`
	CommonLabels struct {
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
	Content string            `json:"content"`
	Embeds  []freshdeskTicket `json:"embeds"`
}

type freshdeskTicket struct {
	Subject     string                 `json:"subject"`
	Description string                 `json:"description"`
	Status      int                    `json:"status"`
	Priority    int                    `json:"priority"`
	Fields      []freshdeskTicketField `json:"fields"`
}

type freshdeskTicketField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

const defaultListenAddress = "127.0.0.1:9095"

var (
	whURL         = flag.String("webhook.url", os.Getenv("FRESHDESK_API"), "Freshdesk API URL.")
	listenAddress = flag.String("listen.address", os.Getenv("LISTEN_ADDRESS"), "Address:Port to listen on.")
)

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
		log.Printf("The Freshdesk API URL doesn't seem to be a valid URL(regex).")
	}
}

func sendWebhook(amo *alertManOut) {
	groupedAlerts := make(map[string][]alertManAlert)

	for _, alert := range amo.Alerts {
		groupedAlerts[alert.Status] = append(groupedAlerts[alert.Status], alert)
	}

	for status, alerts := range groupedAlerts {
		DO := freshdeskOut{}
		RichEmbed := freshdeskTicket{
			Subject:     fmt.Sprintf("[%s:%d] %s", strings.ToUpper(status), len(alerts), amo.CommonLabels.Alertname),
			Description: amo.CommonAnnotations.Summary,
			Fields:      []freshdeskTicketField{},
		}

		if amo.CommonAnnotations.Summary != "" {
			DO.Content = fmt.Sprintf(" === %s === \n", amo.CommonAnnotations.Summary)
		}

		for _, alert := range alerts {
			realname := alert.Labels["instance"]
			if strings.Contains(realname, "localhost") && alert.Labels["exported_instance"] != "" {
				realname = alert.Labels["exported_instance"]
			}

			RichEmbed.Fields = append(RichEmbed.Fields, freshdeskTicketField{
				Name:  fmt.Sprintf("[%s]: %s on %s", strings.ToUpper(status), alert.Labels["alertname"], realname),
				Value: alert.Annotations.Description,
			})
		}

		DO.Embeds = []freshdeskTicket{RichEmbed}

		DOD, _ := json.Marshal(DO)
		println(http.Response.Status)
		http.Post(*whURL, "application/json", bytes.NewReader(DOD))
	}
}

func sendRawPromAlertWarn() {
	badString := `This program is suppose to be fed by alertmanager.` + "\n" +
		`It is not a replacement for alertmanager, it is a ` + "\n" +
		`webhook target for it. Please read the README.md  ` + "\n" +
		`for guidance on how to configure it for alertmanager` + "\n" +
		`or https://prometheus.io/docs/alerting/latest/configuration/#webhook_config`

	log.Print(`/!\ -- You have misconfigured this software -- /!\`)
	log.Print(`--- --                                      -- ---`)
	log.Print(badString)

	DO := freshdeskOut{
		Content: "",
		Embeds: []freshdeskTicket{
			{
				Subject:     "You have misconfigured this software",
				Description: badString,
				Fields:      []freshdeskTicketField{},
			},
		},
	}

	DOD, _ := json.Marshal(DO)
	http.Post(*whURL, "application/json", bytes.NewReader(DOD))
}

func main() {
	flag.Parse()
	checkWhURL(*whURL)

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
			if isRawPromAlert(b) {
				sendRawPromAlertWarn()
				return
			}

			if len(b) > 1024 {
				log.Printf("Failed to unpack inbound alert request - %s...", string(b[:1023]))

			} else {
				log.Printf("Failed to unpack inbound alert request - %s", string(b))
			}

			return
		}
		println("debug")
		sendWebhook(&amo)
	}))
}
