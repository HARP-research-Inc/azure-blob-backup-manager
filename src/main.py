import argparse
from collections import defaultdict
import datetime
import dataclasses
from functools import total_ordering
import os
import re
from typing import Any, Iterable, Literal, Mapping, Sequence
from pydantic import BaseModel, ConfigDict
import zoneinfo
from azure.storage.blob import BlobServiceClient, StandardBlobTier, ContainerClient
import logging
from harp_logfmt import LogfmtFormatter
from typing import TypeVar

T = TypeVar("T")

logger = logging.getLogger("azure-blob-backup-manager")


@dataclasses.dataclass(frozen=True, slots=True, unsafe_hash=True)
class BackupFile:
    filename: str
    timestamp: datetime.datetime
    storage_tier: StandardBlobTier


threshold_resolution = {
    "hourly": datetime.timedelta(hours=1),
    "daily": datetime.timedelta(days=1),
    "weekly": datetime.timedelta(weeks=1),
    "monthly": datetime.timedelta(days=30),
    "yearly": datetime.timedelta(days=365),
}


def process_backup_files(
    files: list[BackupFile], threshold: Literal["hourly", "daily", "weekly", "monthly", "yearly"]
) -> list[BackupFile]:
    """Process backup files based on the threshold.

    Preconditions:
    * files is a list of BackupFile objects, and they all fall into the range that you're considering (IE, if the range is 7 days ago - now, all of the timestamps should be in that range).
    * files is sorted by timestamp in ascending order.
    * files is not empty
    Returns: A list of BackupFile objects that meet the threshold. Anything else may be deleted if not matched by a future call to this function.
    """
    keep = [files[0]]
    last = files[0]
    for file in files[1:]:
        # print(file.timestamp, last.timestamp, file.timestamp - last.timestamp, threshold_resolution[threshold])
        delta = file.timestamp - last.timestamp
        if delta >= threshold_resolution[threshold]:
            logger.debug(
                "Keeping blob %s because duration %s is greater than threshold %s",
                file.filename,
                delta,
                threshold_resolution[threshold],
                extra=dict(data=file),
            )
            keep.append(file)
            last = file
        else:
            logger.debug(
                "Not keeping blob %s because duration %s is less than threshold %s",
                file.filename,
                delta,
                threshold_resolution[threshold],
                extra=dict(data=file),
            )
    return keep


@total_ordering
class ScheduleConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    until: int | None = None
    keep: Literal["hourly", "daily", "weekly", "monthly", "yearly"]
    tier: StandardBlobTier | None = None

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, ScheduleConfig):
            return NotImplemented
        if self.until is None:
            return False
        if other.until is None:
            return True
        return self.until < other.until


class Config(BaseModel):
    schedule: list[ScheduleConfig]
    fileregex: str
    timezone: str | None = None
    containerName: str


def remove_entries_from_list(source: list[T], to_remove: Iterable[T]) -> list[T]:
    """Removes entries from list source that are in to_remove while keeping the order of the source list."""
    to_remove_set = set(to_remove)
    return [x for x in source if x not in to_remove_set]


def process_all_backup_files(files: list[BackupFile], config: Config) -> Mapping[ScheduleConfig, list[BackupFile]]:
    sorted_files = sorted(files, key=lambda x: x.timestamp, reverse=True)
    sorted_schedules = sorted(config.schedule)
    matched: defaultdict[ScheduleConfig, list[BackupFile]] = defaultdict(list)
    current_schedule_index = 0
    current_until = sorted_schedules[current_schedule_index].until
    if current_until is not None:
        current_timestamp = datetime.timedelta(days=current_until)
    else:
        current_timestamp = None
    currently_matched: list[BackupFile] = []
    now = datetime.datetime.now(zoneinfo.ZoneInfo(config.timezone) if config.timezone else datetime.timezone.utc)
    for file in sorted_files:
        if current_timestamp and (now - file.timestamp) > current_timestamp:
            if currently_matched:
                matched[sorted_schedules[current_schedule_index]] = kept = process_backup_files(
                    list(reversed(currently_matched)), sorted_schedules[current_schedule_index].keep
                )
                currently_matched = remove_entries_from_list(currently_matched, kept)
            if current_schedule_index == len(sorted_schedules) - 1:
                break
            current_schedule_index += 1
            current_until = sorted_schedules[current_schedule_index].until
            if current_until is not None:
                current_timestamp = datetime.timedelta(days=current_until)
            else:
                current_timestamp = None
        currently_matched.append(file)
    else:
        if currently_matched:
            matched[sorted_schedules[current_schedule_index]] = process_backup_files(
                list(reversed(currently_matched)), sorted_schedules[current_schedule_index].keep
            )
    return matched


def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as f:
        return Config.model_validate_json(f.read())


def load_azure(config: Config, container_client: ContainerClient) -> list[BackupFile]:
    files: list[BackupFile] = []
    regex = re.compile(config.fileregex)
    for blob in container_client.list_blobs():
        match = regex.match(blob.name)
        if match:
            groups = match.groups()
            timestamp = datetime.datetime(
                *map(int, filter(None, groups[:6])),
                tzinfo=zoneinfo.ZoneInfo(config.timezone) if config.timezone else datetime.timezone.utc,
            )
            storage_tier = blob.blob_tier if blob.blob_tier else StandardBlobTier.HOT
            files.append(BackupFile(blob.name, timestamp, storage_tier))
    return files


def calculate_delta(all_files: list[BackupFile], kept: Mapping[ScheduleConfig, list[BackupFile]]) -> list[BackupFile]:
    total_set = set(all_files)
    kept_set: set[BackupFile] = set()
    for files in kept.values():
        kept_set.update(files)
    return list(total_set - kept_set)


def delete_files(files: list[BackupFile], container_client: ContainerClient, simulation: bool = False) -> int:
    for file in files:
        logger.debug("Deleting blob %s", file.filename, extra=dict(data=file))
    if not simulation:
        container_client.delete_blobs(*(file.filename for file in files))
    return len(files)


def comp_tiers(tier1: StandardBlobTier, tier2: StandardBlobTier) -> int:
    order = [
        StandardBlobTier.ARCHIVE,
        StandardBlobTier.COLD,
        StandardBlobTier.COOL,
        StandardBlobTier.HOT,
    ]  # Order of tiers from cheapest to most expensive
    return order.index(tier1) - order.index(tier2)


def move_files(
    files: Mapping[ScheduleConfig, list[BackupFile]], container_client: ContainerClient, simulation: bool = False
) -> Mapping[tuple[StandardBlobTier, StandardBlobTier], int]:
    moves: list[dict[str, str]] = []
    move_counts: defaultdict[tuple[StandardBlobTier, StandardBlobTier], int] = defaultdict(int)
    for schedule, backup_files in files.items():
        schedule_tier = schedule.tier or StandardBlobTier.HOT
        for file in backup_files:
            comparison = comp_tiers(file.storage_tier, schedule_tier)
            if comparison > 0:
                logger.debug(
                    "Moving blob %s to tier %s",
                    file.filename,
                    schedule_tier.value,
                    extra=dict(data=dict(file=file, tier=schedule_tier, target_tier=schedule_tier)),
                )
                moves.append(dict(name=file.filename, tier=schedule_tier))
                move_counts[(file.storage_tier, schedule_tier)] += 1
            elif comparison == 0:
                logger.debug(
                    "Blob %s is already in tier %s",
                    file.filename,
                    schedule_tier.value,
                    extra=dict(data=dict(file=file, tier=schedule_tier)),
                )
            else:
                logger.debug(
                    "Blob %s is already in a higher tier than %s, not moving up",
                    file.filename,
                    schedule_tier.value,
                    extra=dict(data=dict(file=file, tier=schedule_tier, target_tier=file.storage_tier)),
                )
    if not simulation and moves:
        container_client.set_standard_blob_tier_blobs(None, *moves)
    return move_counts


def act(args: argparse.Namespace):
    config = load_config(args.config)
    client = BlobServiceClient(
        f"https://{args.storage_account_name}.blob.core.windows.net",
        credential=args.storage_account_key,
    )
    simulation = args.simulate == "T"
    container_client = client.get_container_client(config.containerName)
    all_files = load_azure(config, container_client)
    kept = process_all_backup_files(all_files, config)
    delta = calculate_delta(all_files, kept)
    deleted = delete_files(delta, container_client, simulation)
    moves = move_files(kept, container_client, simulation)
    logger.info("Deleted %d blobs", deleted)
    for (source, target), count in moves.items():
        logger.info("Moved %d blobs from %s to %s", count, source, target)


def setup_logger(log_level: str | None, colorize: Literal["auto", "always", "never"] = "auto"):
    if not log_level:
        if log_level_env := os.environ.get("LOG_LEVEL"):
            if log_level_val := getattr(logging, log_level_env, None):
                logger.setLevel(log_level_val)
            else:
                raise ValueError(f"Invalid log level: {log_level_env}")
        else:
            logger.setLevel(logging.INFO)
    else:
        if log_level_val := getattr(logging, log_level, None):
            logger.setLevel(log_level_val)
        else:
            raise ValueError(f"Invalid log level: {log_level}")
    handler = logging.StreamHandler()
    match colorize:
        case "auto":
            colorize_bool = handler.stream.isatty()
        case "always":
            colorize_bool = True
        case "never":
            colorize_bool = False
    formatter = LogfmtFormatter(colorize=colorize_bool)
    formatter.add_custom_formatter(StandardBlobTier, lambda value: value.value)
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def get_value(
    namespace: argparse.Namespace,
    key: str,
    environment_variable: str | None = None,
    default: str | None = None,
    *,
    choices: list[str] | None = None,
) -> str | None:
    if value := getattr(namespace, key):
        if choices and value not in choices:
            raise ValueError(f"Value for {key} is not in the list of choices: {choices}")
        return value
    if environment_variable and (value := os.environ.get(environment_variable)):
        if choices and value not in choices:
            raise ValueError(
                f"Value for {key} from environment variable {environment_variable} is not in the list of choices: {choices}"
            )
        return value
    if default:
        if choices and default not in choices:
            raise ValueError(f"Default value for {key} is not in the list of choices: {choices}")
        return default
    return None


def main(args: Sequence[str] | None = None):
    parser = argparse.ArgumentParser(description="Process Azure backups")
    simulate_choices = ["T", "F"]
    parser.add_argument(
        "--simulate",
        help="Simulate the actions without actually doing them (can also use environment variable SIMULATE)",
        choices=simulate_choices,
    )
    parser.add_argument(
        "--config", help="Path to the config file (can also use environment variable CONFIG_PATH, default: config.json)"
    )
    log_level_choices = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    parser.add_argument(
        "--log-level",
        help="Log level (can use environment variable LOG_LEVEL, default: INFO)",
        choices=log_level_choices,
    )
    colorize_choices = ["auto", "always", "never"]
    parser.add_argument(
        "--colorize",
        help="Colorize the log output (can use environment variable COLORIZE, default: auto)",
        choices=colorize_choices,
    )
    parser.add_argument(
        "--storage-account-name",
        help="Azure storage account name (can also use environment variable AZURE_STORAGE_ACCOUNT)",
    )
    parser.add_argument(
        "--storage-account-key", help="Azure storage account key (can also use environment variable AZURE_STORAGE_KEY)"
    )
    parsed_initial = parser.parse_args(args)
    parsed = argparse.Namespace(
        simulate=get_value(parsed_initial, "simulate", "SIMULATE", "F", choices=simulate_choices),
        config=get_value(parsed_initial, "config", "CONFIG_PATH", "config.json"),
        log_level=get_value(parsed_initial, "log_level", "LOG_LEVEL", "INFO", choices=log_level_choices),
        colorize=get_value(parsed_initial, "colorize", "COLORIZE", "auto", choices=colorize_choices),
        storage_account_name=get_value(parsed_initial, "storage_account_name", "AZURE_STORAGE_ACCOUNT"),
        storage_account_key=get_value(parsed_initial, "storage_account_key", "AZURE_STORAGE_KEY"),
    )
    setup_logger(parsed.log_level, parsed.colorize)
    logger.debug("Args recieved:", extra=dict(data=parsed))
    return act(parsed)


if __name__ == "__main__":
    main()
