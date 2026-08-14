package scmbench.rules.cis_2_2_4_test

import rego.v1

import data.scmbench.rules.cis_2_2_4
import data.scmbench.testdata

# A control no API can answer reports MANUAL for every resource, including one
# the fetcher could read everything about: the gap is in what Jenkins exposes,
# not in what the token could reach.
test_always_manual if {
	r := cis_2_2_4.result with input as testdata.controller_input({})
	r.status == "MANUAL"
}

test_manual_even_for_an_empty_resource if {
	r := cis_2_2_4.result with input as testdata.input_for({})
	r.status == "MANUAL"
}
