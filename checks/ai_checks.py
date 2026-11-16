"""AI check: CCF-09. An agent may only use approved tools, and any tool that writes needs human approval."""
import json
import os

from .common import FAIL, PASS, ROOT, Result, latest_evidence, missing, rel, save_evidence

AI_DIR = os.path.join(ROOT, "ai")


def collect_ai_config(who):
    with open(os.path.join(AI_DIR, "agent_config.json")) as f:
        agent = json.load(f)
    with open(os.path.join(AI_DIR, "approved_tools.json")) as f:
        approved = json.load(f)
    return save_evidence("ai_agent_config", {"agent": agent, "approved": approved}, who)


def evaluate_ai_agent_tools_approved(env=None, today=None):
    path, env = (None, env) if env is not None else latest_evidence("ai_agent_config")
    if env is None:
        return missing("ai_agent_config")
    agent = env["data"]["agent"]
    approved = set(env["data"]["approved"].get("approved_tools", []))
    problems = []
    if not agent.get("owner"):
        problems.append("No owner named for the agent")
    for t in agent.get("tools", []):
        if t["name"] not in approved:
            problems.append(f"{t['name']}: not on the approved list")
        if t.get("access") == "write" and not t.get("requires_human_approval"):
            problems.append(f"{t['name']}: writes data without human approval")
    metric = f"{len(agent.get('tools', []))} tool(s)"
    if problems:
        return Result(FAIL, f"Agent '{agent.get('name')}' breaks {len(problems)} rule(s)", metric, problems, rel(path))
    return Result(PASS, f"Agent '{agent.get('name')}' has an owner and uses only approved, gated tools",
                  metric, [], rel(path))
