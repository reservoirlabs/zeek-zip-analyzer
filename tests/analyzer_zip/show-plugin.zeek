# @TEST-EXEC: zeek -NN Reservoir::Analyzer_ZIP |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
