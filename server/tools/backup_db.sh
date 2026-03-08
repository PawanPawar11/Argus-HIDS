#!/bin/bash
# HIDS Database Backup Script
# Compatible with Fedora/RHEL (requires: gzip — install with: sudo dnf install -y gzip)

BACKUP_DIR="database/backups"
DB_FILE="database/hids.db"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

if [ ! -f "$DB_FILE" ]; then
    echo "❌ Database file not found: $DB_FILE"
    exit 1
fi

cp $DB_FILE "$BACKUP_DIR/hids_backup_$TIMESTAMP.db"
gzip "$BACKUP_DIR/hids_backup_$TIMESTAMP.db"
echo "✅ Backup created: $BACKUP_DIR/hids_backup_$TIMESTAMP.db.gz"

# Remove backups older than 30 days
find "$BACKUP_DIR" -name "hids_backup_*.db.gz" -mtime +30 -delete
echo "🧹 Old backups (>30 days) cleaned up"