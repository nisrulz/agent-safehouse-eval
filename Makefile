.PHONY: help eval eval-clean report check

help:
	@echo "make eval [version=V]    run the eval against Safehouse"
	@echo "make eval-clean          run the eval, then move the rig into rig/.trash/"
	@echo "make report version=V    regenerate the CSV report from rig/results.txt"
	@echo "make check               syntax-check the shell scripts"

eval:
	./run-eval.sh $(if $(version),--version $(version))

eval-clean:
	./run-eval.sh --cleanup

report:
	@test -n "$(version)" || { echo "usage: make report version=0.13.0"; exit 1; }
	tools/gen-report.sh rig/results.txt reports/eval-report-$(version).csv $(version) rig

check:
	bash -n run-eval.sh
	bash -n probes/battery.sh
	bash -n tools/gen-spot.sh
	bash -n tools/gen-report.sh
