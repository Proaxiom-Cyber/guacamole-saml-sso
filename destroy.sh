#!/bin/bash
# Stops and removes the containers, networks, images and volumes of this stack.
# It does not delete ./data. Delete that folder as well for a full reset.
set -e
docker compose down --volumes --rmi all --remove-orphans
echo "Done. Delete ./data as well to reset the database."
