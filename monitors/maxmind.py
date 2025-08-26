# Copyright 2022 Scalyr Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------
#
# An example ScalyrMonitor plugin to demonstrate how they can be written.
#
# Note, this can be run in standalone mode by:
#     python -m scalyr_agent.run_monitor -c "{ gauss_mean: 0.5 }" scalyr_agent.builtin_monitors.test_monitor
#
# author:  Steven Czerwinski <czerwin@scalyr.com>

from __future__ import absolute_import

__author__ = "jmora@scalyr.com"

import random
import json
from scalyr_agent import ScalyrMonitor
import subprocess
import sys
import requests

class RandomMonitor(ScalyrMonitor):
    """A Scalyr agent monitor that records random numbers.
    """
    def _initialize(self):
        """Performs monitor-specific initialization."""
        # TODO:  Is it better to have this, or just require that classes override __init__ and do their
        # initialization that way.  If we do that, then they must know the argument list for __init__.

        # Useful instance variables:
        #   self._sample_interval_secs:  The number of seconds between calls to gather_sample.
        #   self._config:  The MonitorConfig object containing the configuration for this monitor instance as retrieved
        #                  from configuration file.  It is essentially like a dict but has some methods for validating
        #                  field values.
        #   self._logger:  The logger instance to report errors/warnings/etc.
        #   self.log_config: The dict containing the configuration for how the metric log created by the
        #                    this module should be saved.  It uses the same fields as the entries in agent.json's
        #                    "logs" section.  You can set the path for the log file, as well as the attributes
        #                    such as the parser, etc.
        #  self._log_write_rate:  The allowed average number of bytes per second that can be written to the metric
        #                         log for this monitor.  If this monitor tries to emit more than these number of
        #                         bytes, then log lines are dropped (and a warning message is emitted to the log
        #                         indicating how many lines were dropped).  The actual rate limit is calculated using
        #                         a leaky bucket algorithm, where this is the fill rate (per second) of the bucket.
        #  self._log_max_write_burst:  The maximum allowed log write burst rate.  This is used in conjunction with
        #                              self._log_write_rate to rate limit how many bytes this monitor can write to
        #                              the metric log.  The actual rate limit is calculated using a leaky bucket
        #                              algorithm, where this is the bucket size.

        self.__counter = 0
        # A required configuration field.

        self.__powerquery = self._config.get(
            "powerquery",
            convert_to=str,
            default= "serverHost = * | group count() by serverHost",
            required_field=True
        )
        self.__url = self._config.get(
            "url",
            convert_to=str,
            default= "https://app.scalyr.com/api/powerQuery"
        )
        self.__startTime = self._config.get(
            "startTime",
            convert_to=str,
            default= "4h",
        )
        self.__endTime = self._config.get(
            "endTime",
            convert_to=str,
            default= "0h",
        )
        self.__token = self._config.get(
            "token",
            convert_to=str,
            default= "",
            required_field=True
        )
        # An optional configuration field.
        self.__database = self._config.get(
            "database",
            convert_to=str,
            default="/data/GeoLite2-ASN.mmdb"
        )
        #subprocess.check_call([sys.executable, "-m", "pip", "install", "pandas"])
    #    subprocess.check_call([sys.executable, "-m", "pip", "install", "tabulate maxmind pandas"])
        packages = ["pandas", "geoip2", "tabulate"]
        for package in packages:
          subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    def gather_sample(self):
        import pandas as pd
        import numpy as np
        import geoip2.database
        url = self.__url
        payload = json.dumps({
          "token": self.__token,
          "query": self.__powerquery,
          "startTime": self.__startTime,
          "endTime": self.__endTime
        })
        headers = {
          'Content-Type': 'application/json',
          'Cookie': 'sp=67099796-f662-4eb9-8443-f7239b820fb7'
        }
        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        input_dict = json.loads(response.text)
        # Parse the input string into a Python dictionary
        # Extract the "values" field from the dictionaryVV

        # Parse the input string into a Python dictionary
        # Extract the "values" field from the dictionary
        values = input_dict['values']
        columns = input_dict['columns']
#        print(columns)
        columns_array = []
        for column in columns:
            columns_array.append(column['name'])
        columns = columns_array
#        print(columns)
        # Convert the values list into a pandas DataFrame
        df = pd.DataFrame(values, columns=columns)
#        print(df.to_string())
        self.__counter += 1
        # Be sure to use emit_values to record the statistics the monitor wishes to send to Scalyr.
#        self._logger.emit_value(
#             "foo",
#             str(df.to_json())
#        )
        reader = geoip2.database.Reader(self.__database)
        for index, row in df.iterrows():
            ip_address = row['Destination_IP']
            a = row.to_dict()
            try:
              # Look up the city information for the IP address
              r = reader.city(ip_address)
              # Extract the city, state, and country information
              extra_fields = {}
	# Extract the city, state, and country information
	# Add the data to the extra_fields dictionary
              extra_fields["ip"] = ip_address
              extra_fields["geo"] = str(r)
              self._logger.emit_value(
                "enriched",
                str(a),
                extra_fields=extra_fields
            )
            except geoip2.errors.AddressNotFoundError:
              self._logger.emit_value(
                "non-enriched",
                str(a)
              )
              continue
        reader.close()

        # You may also emit full log lines to the metric log by using the special emit_to_metric_log=True parameter.
        # Otherwise, the log lines will be assumed to be errors and will go to the agent.log
        # self._logger.info('This will go to the metric log', emit_to_metric_log=True)
