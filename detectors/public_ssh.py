import argparse
import ipaddress
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


FAILED_LOGIN_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}).*"
    r"Failed password for "
    r"(?:(?:invalid user )?(?P<username>[A-Za-z0-9._-]+)|(?P<username_unknown>\S+)) "
    r"from (?P<src_ip>\d{1,3}(?:\.\d{1,3}){3}) "
)

ACCEPTED_LOGIN_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}).*"
    r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for "
    r"(?P<username>[A-Za-z0-9._-]+) "
    r"from (?P<src_ip>\d{1,3}(?:\.\d{1,3}){3}) "
)

DEFAULT_SSH_USERNAMES = {
    "root",
    "admin",
    "administrator",
    "ubuntu",
    "ec2-user",
    "centos",
    "debian",
    "oracle",
    "test",
    "user",
    "guest",
}


def parse_log_time(month: str, day: str, time_value: str, year: int) -> datetime:
    raw_time = f"{year} {month} {day} {time_value}"
    return datetime.strptime(raw_time, "%Y %b %d %H:%M:%S")


def parse_auth_log(log_path: str, year: int) -> list[dict]:
    events = []

    with open(log_path, "r", encoding="utf-8") as file:
        for line in file:
            failed_match = FAILED_LOGIN_PATTERN.search(line)
            accepted_match = ACCEPTED_LOGIN_PATTERN.search(line)

            if failed_match:
                username = failed_match.group("username") or failed_match.group("username_unknown")
                events.append(
                    {
                        "timestamp": parse_log_time(
                            failed_match.group("month"),
                            failed_match.group("day"),
                            failed_match.group("time"),
                            year,
                        ),
                        "event_type": "failed",
                        "src_ip": failed_match.group("src_ip"),
                        "username": username,
                        "auth_method": None,
                        "raw": line.strip(),
                    }
                )
                continue

            if accepted_match:
                events.append(
                    {
                        "timestamp": parse_log_time(
                            accepted_match.group("month"),
                            accepted_match.group("day"),
                            accepted_match.group("time"),
                            year,
                        ),
                        "event_type": "accepted",
                        "src_ip": accepted_match.group("src_ip"),
                        "username": accepted_match.group("username"),
                        "auth_method": accepted_match.group("method"),
                        "raw": line.strip(),
                    }
                )

    return sorted(events, key=lambda event: event["timestamp"])


def load_security_group(security_group_path: str | None) -> dict | None:
    if not security_group_path:
        return None

    path = Path(security_group_path)

    if not path.exists():
        raise FileNotFoundError(f"Security Group file not found: {security_group_path}")

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def is_public_cidr(cidr: str) -> bool:
    return cidr in {"0.0.0.0/0", "::/0"}


def is_ssh_publicly_exposed(security_group: dict | None) -> bool:
    if not security_group:
        return False

    for permission in security_group.get("IpPermissions", []):
        protocol = permission.get("IpProtocol")
        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")

        if protocol not in {"tcp", "-1"}:
            continue

        if from_port is None or to_port is None:
            continue

        ssh_port_in_range = from_port <= 22 <= to_port

        if not ssh_port_in_range:
            continue

        for ip_range in permission.get("IpRanges", []):
            if is_public_cidr(ip_range.get("CidrIp", "")):
                return True

        for ipv6_range in permission.get("Ipv6Ranges", []):
            if is_public_cidr(ipv6_range.get("CidrIpv6", "")):
                return True

    return False


def parse_allowlist(allowlist: list[str]) -> list[ipaddress._BaseNetwork]:
    networks = []

    for item in allowlist:
        networks.append(ipaddress.ip_network(item, strict=False))

    return networks


def is_allowed_ip(src_ip: str, allowlist_networks: list[ipaddress._BaseNetwork]) -> bool:
    ip = ipaddress.ip_address(src_ip)

    return any(ip in network for network in allowlist_networks)


def find_success_after_failures(
    src_ip: str,
    window_end: datetime,
    events: list[dict],
    success_window_minutes: int,
) -> dict | None:
    success_deadline = window_end + timedelta(minutes=success_window_minutes)

    for event in events:
        if event["event_type"] != "accepted":
            continue

        if event["src_ip"] != src_ip:
            continue

        if window_end <= event["timestamp"] <= success_deadline:
            return event

    return None


def calculate_severity(
    ssh_public: bool,
    is_allowed: bool,
    failed_count: int,
    unique_user_count: int,
    default_username_count: int,
    success_after_failure: bool,
) -> str:
    if is_allowed and not success_after_failure:
        return "LOW"

    if ssh_public and success_after_failure:
        return "CRITICAL"

    if success_after_failure:
        return "HIGH"

    if ssh_public and unique_user_count >= 3 and default_username_count >= 2:
        return "HIGH"

    if failed_count >= 5:
        return "MEDIUM"

    return "LOW"


def build_risk_summary(
    ssh_public: bool,
    is_allowed: bool,
    unique_user_count: int,
    default_usernames: set[str],
    success_event: dict | None,
) -> str:
    reasons = []

    if ssh_public:
        reasons.append("Security Group에서 SSH 포트가 인터넷 전체에 공개되어 있습니다.")

    if is_allowed:
        reasons.append("출발지 IP가 허용 목록에 포함되어 있어 운영자 실수 가능성이 있습니다.")
    else:
        reasons.append("출발지 IP가 허용 목록에 포함되어 있지 않습니다.")

    if unique_user_count >= 3:
        reasons.append("여러 계정명으로 SSH 로그인을 시도했습니다.")

    if default_usernames:
        usernames = ", ".join(sorted(default_usernames))
        reasons.append(f"기본 계정명 또는 추측하기 쉬운 계정명이 사용되었습니다: {usernames}")

    if success_event:
        reasons.append("반복 실패 이후 동일 IP에서 성공 로그인이 발생했습니다.")

    return " ".join(reasons)


def detect_public_ssh_bruteforce(
    events: list[dict],
    ssh_public: bool,
    allowlist_networks: list[ipaddress._BaseNetwork],
    threshold: int,
    window_minutes: int,
    success_window_minutes: int,
) -> list[dict]:
    failed_events_by_ip = defaultdict(list)

    for event in events:
        if event["event_type"] == "failed":
            failed_events_by_ip[event["src_ip"]].append(event)

    findings = []

    for src_ip, failed_events in failed_events_by_ip.items():
        sorted_failed_events = sorted(failed_events, key=lambda event: event["timestamp"])

        for index, current_event in enumerate(sorted_failed_events):
            window_start = current_event["timestamp"]
            window_end = window_start + timedelta(minutes=window_minutes)

            failed_events_in_window = [
                event
                for event in sorted_failed_events[index:]
                if window_start <= event["timestamp"] <= window_end
            ]

            if len(failed_events_in_window) < threshold:
                continue

            usernames = {
                event["username"]
                for event in failed_events_in_window
                if event.get("username")
            }

            default_usernames = usernames.intersection(DEFAULT_SSH_USERNAMES)
            success_event = find_success_after_failures(
                src_ip=src_ip,
                window_end=window_end,
                events=events,
                success_window_minutes=success_window_minutes,
            )
            allowed = is_allowed_ip(src_ip, allowlist_networks)

            severity = calculate_severity(
                ssh_public=ssh_public,
                is_allowed=allowed,
                failed_count=len(failed_events_in_window),
                unique_user_count=len(usernames),
                default_username_count=len(default_usernames),
                success_after_failure=success_event is not None,
            )

            finding = {
                "severity": severity,
                "detection": "Public SSH Exposure with Brute Force Indicators",
                "resource": "SSH Service",
                "src_ip": src_ip,
                "allowed_ip": allowed,
                "ssh_publicly_exposed": ssh_public,
                "failed_count": len(failed_events_in_window),
                "unique_user_count": len(usernames),
                "usernames": sorted(usernames),
                "default_usernames": sorted(default_usernames),
                "success_after_failure": success_event is not None,
                "success_username": success_event["username"] if success_event else None,
                "success_time": success_event["timestamp"] if success_event else None,
                "window_start": window_start,
                "window_end": window_end,
                "condition": (
                    f"{window_minutes}분 이내 동일 출발지 IP에서 "
                    f"SSH 로그인 실패 {threshold}회 이상 발생"
                ),
                "risk": build_risk_summary(
                    ssh_public=ssh_public,
                    is_allowed=allowed,
                    unique_user_count=len(usernames),
                    default_usernames=default_usernames,
                    success_event=success_event,
                ),
                "recommendation": (
                    "SSH 접근 대상을 신뢰 IP 또는 VPN 대역으로 제한하고, "
                    "비밀번호 인증을 비활성화하며, SSH Key 기반 인증과 "
                    "로그 모니터링을 적용해야 합니다."
                ),
            }

            findings.append(finding)
            break

    return sorted(
        findings,
        key=lambda finding: {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
        }.get(finding["severity"], 0),
        reverse=True,
    )


def print_findings(findings: list[dict]) -> None:
    if not findings:
        print("[INFO] No suspicious public SSH activity detected.")
        return

    for finding in findings:
        print(f"[{finding['severity']}] {finding['detection']}")
        print(f"Resource: {finding['resource']}")
        print(f"Source IP: {finding['src_ip']}")
        print(f"Allowed IP: {finding['allowed_ip']}")
        print(f"SSH Publicly Exposed: {finding['ssh_publicly_exposed']}")
        print(f"Failed Count: {finding['failed_count']}")
        print(f"Unique User Count: {finding['unique_user_count']}")
        print(f"Usernames: {', '.join(finding['usernames'])}")
        print(f"Default Usernames: {', '.join(finding['default_usernames']) or 'None'}")
        print(f"Success After Failure: {finding['success_after_failure']}")

        if finding["success_after_failure"]:
            print(f"Success Username: {finding['success_username']}")
            print(f"Success Time: {finding['success_time']}")

        print(f"Window: {finding['window_start']} ~ {finding['window_end']}")
        print(f"Condition: {finding['condition']}")
        print(f"Risk: {finding['risk']}")
        print(f"Recommendation: {finding['recommendation']}")
        print("-" * 80)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect public SSH exposure with brute force indicators"
    )
    parser.add_argument(
        "log_path",
        help="Path to SSH authentication log file",
    )
    parser.add_argument(
        "--security-group",
        help="Path to Security Group JSON file",
    )
    parser.add_argument(
        "--allowlist",
        nargs="*",
        default=[],
        help="Allowed source IPs or CIDR ranges. Example: 10.10.10.10/32",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed login threshold",
    )
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=5,
        help="Failed login detection time window in minutes",
    )
    parser.add_argument(
        "--success-window-minutes",
        type=int,
        default=10,
        help="Time window for checking successful login after failures",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=2026,
        help="Year value used for syslog timestamp parsing",
    )

    args = parser.parse_args()

    events = parse_auth_log(args.log_path, args.year)
    security_group = load_security_group(args.security_group)
    ssh_public = is_ssh_publicly_exposed(security_group)
    allowlist_networks = parse_allowlist(args.allowlist)

    findings = detect_public_ssh_bruteforce(
        events=events,
        ssh_public=ssh_public,
        allowlist_networks=allowlist_networks,
        threshold=args.threshold,
        window_minutes=args.window_minutes,
        success_window_minutes=args.success_window_minutes,
    )

    print_findings(findings)


if __name__ == "__main__":
    main()