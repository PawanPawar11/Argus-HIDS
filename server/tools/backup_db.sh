#!/bin/bash
BACKUP_DIR="database/backups"
DB_FILE="database/hids.db"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR
cp $DB_FILE "$BACKUP_DIR/hids_backup_$TIMESTAMP.db"
gzip "$BACKUP_DIR/hids_backup_$TIMESTAMP.db"
echo "✅ Backup created"
