#!/bin/bash
# Script to test parameter handling for the deployment scripts

echo "Testing deployment parameter handling"
echo "====================================="

# Default values
ENVIRONMENT="dev"
PASSWORD=""

# Parse command line arguments
while [ "$#" -gt 0 ]; do
  case "$1" in
    --env)
      ENVIRONMENT="$2"
      shift 2
      ;;
    --password)
      PASSWORD="$2"
      shift 2
      ;;
    *)
      echo "Unknown parameter: $1"
      exit 1
      ;;
  esac
done

echo "Environment: $ENVIRONMENT"
echo "Password provided: $(if [ -n "$PASSWORD" ]; then echo "Yes"; else echo "No"; fi)"

# Test parameter-overrides with default empty password
echo -e "\nTesting with default empty password:"
PARAMS="Environment=\"$ENVIRONMENT\""
if [ -n "$PASSWORD" ]; then
  PARAMS="$PARAMS AppPassword=\"$PASSWORD\""
fi
echo "Parameter overrides: $PARAMS"
echo "sam deploy --parameter-overrides $PARAMS"

# Test with non-empty password
echo -e "\nTesting with non-empty password:"
TEST_PASSWORD="testpassword"
PARAMS="Environment=\"$ENVIRONMENT\""
if [ -n "$TEST_PASSWORD" ]; then
  PARAMS="$PARAMS AppPassword=\"$TEST_PASSWORD\""
fi
echo "Parameter overrides: $PARAMS"
echo "sam deploy --parameter-overrides $PARAMS"

echo -e "\nTest completed successfully!"
