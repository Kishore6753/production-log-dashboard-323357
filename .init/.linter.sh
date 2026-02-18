#!/bin/bash
cd /home/kavia/workspace/code-generation/production-log-dashboard-323357/production_log_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

