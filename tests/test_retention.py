from src.main import process_backup_files, BackupFile
import datetime
from azure.storage.blob import StandardBlobTier


def test_hourly_retention_small():
    times = [
        datetime.datetime(2024, 10, 31, 15, 0, tzinfo=datetime.timezone.utc),
        datetime.datetime(2024, 10, 31, 15, 30, tzinfo=datetime.timezone.utc),
        datetime.datetime(2024, 10, 31, 16, 0, tzinfo=datetime.timezone.utc),
        datetime.datetime(2024, 10, 31, 16, 30, tzinfo=datetime.timezone.utc),
        datetime.datetime(2024, 10, 31, 17, 0, tzinfo=datetime.timezone.utc),
    ]
    files = [f"file_{i}.txt" for i in range(5)]
    backup_files = [BackupFile(file, time, StandardBlobTier.HOT) for file, time in zip(files, times)]
    processed = process_backup_files(backup_files, "hourly")
    assert len(processed) == 3
    assert processed[0] == backup_files[0]
    assert processed[1] == backup_files[2]
    assert processed[2] == backup_files[4]


def test_daily_retention_small():
    times = [
        datetime.datetime(2024, 10, 31, tzinfo=datetime.timezone.utc),
        datetime.datetime(2024, 11, 1, tzinfo=datetime.timezone.utc),
        datetime.datetime(2024, 11, 1, 12, tzinfo=datetime.timezone.utc),
        datetime.datetime(2024, 11, 2, tzinfo=datetime.timezone.utc),
        datetime.datetime(2024, 11, 4, tzinfo=datetime.timezone.utc),
    ]
    files = [f"file_{i}.txt" for i in range(5)]
    backup_files = [BackupFile(file, time, StandardBlobTier.HOT) for file, time in zip(files, times)]
    processed = process_backup_files(backup_files, "daily")
    assert len(processed) == 4
    assert processed[0] == backup_files[0]
    assert processed[1] == backup_files[1]
    assert processed[2] == backup_files[3]
    assert processed[3] == backup_files[4]
