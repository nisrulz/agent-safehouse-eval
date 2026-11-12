.PHONY: help eval eval-clean report allowlist check

help:
	@echo "make eval [version=V]    run the eval against Safehouse"
	@echo "make eval-clean          run the eval, then move the rig into rig/.trash/"
	@echo "make report version=V    regenerate the CSV report from rig/results.txt"
	@echo "make allowlist           run the hostname allowlist stage (loopback proxy)"
	@echo "make check               syntax-check the shell scripts"

eval:
	./run-eval.sh $(if $(version),--version $(version))

eval-clean:
	./run-eval.sh --cleanup

report:
	@test -n "$(version)" || { echo "usage: make report version=0.13.0"; exit 1; }
	tools/gen-report.sh rig/results.txt reports/eval-report-$(version).csv $(version) rig

allowlist:
	./tools/allowlist-eval.sh

check:
	bash -n run-eval.sh
	bash -n probes/battery.sh
	bash -n tools/gen-spot.sh
	bash -n tools/gen-report.sh
	bash -n tools/allowlist-eval.sh
	python3 -m py_compile tools/proxy-allowlist.py
