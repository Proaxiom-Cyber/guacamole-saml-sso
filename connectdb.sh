#!/bin/bash
docker compose exec postgres psql -U guacamole_user -d guacamole_db
