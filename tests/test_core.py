 
import pytest
import asyncio
from logsentry.core import LogParser

@pytest.fixture
def parser():
    return LogParser()

@pytest.mark.asyncio
async def test_parse_line_valid(parser):
    line = "Apr 15 14:30:22 host sshd[1234]: Failed password for user root from 192.168.1.1"
    result = await parser.parse_line(line)
    assert result is not None
    assert result["user"] == "root"
    assert result["ip"] == "192.168.1.1"

@pytest.mark.asyncio
async def test_parse_line_invalid(parser):
    line = "Invalid log line"
    result = await parser.parse_line(line)
    assert result is None