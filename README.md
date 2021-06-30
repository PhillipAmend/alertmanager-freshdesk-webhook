
# Freshalert

Freshalert is a tool for transforming Alertmanager alerts into Freshdesk tickets.

## Usage

### Enrvionment Variables
In order to run the tool you have to export serveral ENV variables.
Either in you local ENV or in the [deployment.yaml](./examples/k8s/deployment.yaml)


| ENV                   | Required              | Example        | Default       |
|-----------------------|-----------------------|----------------|---------------|
| FRESHSERVICE_API      | Yes                   | "https://yourcompany.freshservice.com/api/v2/tickets"         |  -       |
| REQUESTER_ID          | Yes                   | 27000695915    |  -            |
| FRESHSERVICE_TOKEN    | Yes                   | 7ZbssdNvsfpadummUvpchPK        |  -       |
| LISTEN_ADDRESS        | No                    | 9095           |  9095       |



### Alertmanager Config
You have to create a Webhook receiver configuration in your alertmanager.yaml
Eg.:
```yaml
route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 1s
  repeat_interval: 10s
  receiver: freshdesk-webhook
inhibit_rules:
- source_match:
    severity: 'critical'
  target_match:
    severity: 'warning'
  equal: ['alertname']
# This is an example webhook receiver config
receivers:
  - name: 'freshdesk-webhook'
    webhook_configs:
      - url: 'http://127.0.0.1:9095'
```


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](https://choosealicense.com/licenses/mit/)