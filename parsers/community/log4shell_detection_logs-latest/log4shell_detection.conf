//Inject this into the top your access log and catalina parsers to pick up log4shell data

//scans for log4j
    {
      id: "jndi_match1",
      format: "^\\d+-\\d+-\\d+\\s\\d+:\\d+:\\d+(,\\d+)?\\s\\w+\\s.*\\W\\.*\\{jndi:\\w+://[^\/]+\/[^\/]+\\}"
      attributes: {dataset: "catalina", description: "jndi lookup in default catalina logs", severity: "5"}
    }
    {
      id: "jndi_match",
      format: "^\\d+\\.\\d+\\.\\d+\\.\\d+ .*\\W\\.*(\\{jndi:\\w+://[^\/]+\/[^\/]+\\}|%24%7Bjndi%3A\\w+%3A%2F%2F[^%]+%)"
	  attributes: {description: "jndi lookup in default access logs", severity: "4"}
    },
      {
      id: "jndi_match",
      format: ".*\\{jndi:$protocol$://$remote_server$\/$payload$\\}"
	  attributes: { description: "jndi lookup", severity: "4"}
    },
    
      {
      id: "jndi_match",
      format: ".*%24%7Bjndi%3A$protocol$%3A%2F%2F$remote_server$%3A$port$%2F%23$payload$%7D"
	  attributes: { description: "jndi lookup url encoded", severity: "4"}
    },
      {
      id: "jndi_match",
      format: ".*%24%7Bjndi%3A$protocol$%3A%2F%2F$remote_server$%2F%23$payload$%7D"
	  attributes: { description: "jndi lookup url encoded", severity: "4"}
    },
    {
      id: "jndi_match",
      format: ".*Error looking up JNDI resource .*"
      attributes: {dataset: "catalina", description: "JNDI Resource Lookup Fail"}

    }
