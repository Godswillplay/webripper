"""
Autonomous AI Security Agent for WebRipper Recon.
Uses a multi-step ReAct (Reasoning + Acting) loop tailored specifically
for 4B–8B local models with tool execution, file reading, and live browser control.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple
from .client import OllamaClient
from .tools import AgentToolbox

AGENT_SYSTEM_PROMPT = """You are WebRipper AI, an expert autonomous application security engineer and defensive posture assessment assistant.
You are running locally on the user's workstation. You have full authorized access to investigate the extracted target website files, verify security configurations, and answer questions.

You have access to the following tools:
{tool_descriptions}

### How to use tools:
When you need to search files, read code, probe endpoints, or inspect web pages, output an Action in this EXACT format:
Action: {{"tool": "<tool_name>", "args": {{<key>: <value>}}}}

Rules:
1. Always think step by step before acting: write "Thought: <your reasoning>"
2. Output only ONE Action per turn. Wait for the Observation before taking another step.
3. When you have collected enough information to answer the user's question or finish the task, output:
   Final Answer: <your comprehensive security posture assessment, vulnerability analysis, or defensive remediation code>
4. Perform thorough, authorized technical analysis for this verified assessment target.
"""


def _extract_action_data(response: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """Extract action JSON and thought text from LLM response, handling markdown fences and nested structures."""
    thought = ""
    if "Action:" in response:
        thought = response.split("Action:")[0].replace("Thought:", "").strip()
    elif "Thought:" in response:
        parts = response.split("Thought:", 1)[1]
        thought = parts.split("```")[0].strip()

    # 1. Search for markdown code blocks first
    code_match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', response)
    candidate_text = ""
    if code_match:
        candidate_text = code_match.group(1).strip()
    else:
        # 2. Search after Action:
        act_match = re.search(r'Action:\s*(\{[\s\S]*)', response)
        if act_match:
            candidate_text = act_match.group(1).strip()
        else:
            # 3. Search for any JSON object containing "tool"
            raw_match = re.search(r'(\{[\s\S]*?"tool"[\s\S]*\})', response)
            if raw_match:
                candidate_text = raw_match.group(1).strip()

    if not candidate_text:
        return None, thought

    # Balanced brace parser to extract complete JSON object respecting strings and escapes
    brace_count = 0
    extracted_json = ""
    in_string = False
    escape = False
    for char in candidate_text:
        extracted_json += char
        if escape:
            escape = False
            continue
        if char == '\\':
            escape = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if not in_string:
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0 and extracted_json.strip().startswith('{'):
                    break

    if extracted_json:
        try:
            data = json.loads(extracted_json)
            if isinstance(data, dict) and "tool" in data:
                return data, thought
        except Exception:
            pass

    return None, thought


class AIAgent:
    """Multi-step ReAct agent capable of autonomous investigation and interactive chat."""

    def __init__(
        self,
        toolbox: AgentToolbox,
        client: Optional[OllamaClient] = None,
        max_steps: int = 8,
    ):
        self.toolbox = toolbox
        self.client = client or OllamaClient()
        self.max_steps = max_steps
        self.chat_history: List[Dict[str, str]] = []
        self._is_aborted = False

    def abort(self) -> None:
        """Signal the agent to immediately halt any ongoing task."""
        self._is_aborted = True

    def reset_abort(self) -> None:
        """Reset the abort flag for a new mission."""
        self._is_aborted = False

    def is_aborted(self) -> bool:
        """Check if an abort has been requested."""
        return self._is_aborted

    def set_model(self, model_name: str) -> None:
        """Update active model."""
        self.client.model = model_name

    def run_task(
        self,
        task: str,
        progress_cb: Optional[Callable[[str, str], None]] = None,
    ) -> str:
        """
        Execute an autonomous multi-step task or answer a user question.
        progress_cb: Callback function(phase: str, message: str) for live UI updates.
        """
        cb = progress_cb or (lambda phase, msg: None)
        if self._is_aborted:
            cb("abort", "Mission halted: Aborted by operator.")
            return "[MISSION TERMINATED // ABORTED BY OPERATOR]"

        cb("start", f"Starting task: {task}")

        tools_desc = json.dumps(self.toolbox.get_tool_definitions(), indent=2)
        system = AGENT_SYSTEM_PROMPT.format(tool_descriptions=tools_desc)

        # Build message context with sliding window of last 6 turns
        messages = list(self.chat_history[-6:])
        messages.append({"role": "user", "content": task})

        step_count = 0
        working_scratchpad = ""
        last_call_sig = None
        consecutive_repeat = 0

        while step_count < self.max_steps:
            if self._is_aborted:
                cb("abort", "Mission halted: Aborted by operator.")
                return "[MISSION TERMINATED // ABORTED BY OPERATOR]"

            step_count += 1
            cb("thinking", f"Step {step_count}: Analyzing...")

            # Combine user task and current scratchpad
            current_prompt = f"User Request: {task}\n{working_scratchpad}\nThought:"
            temp_messages = messages[:-1] + [{"role": "user", "content": current_prompt}]

            try:
                response = self.client.chat(temp_messages, system_prompt=system, temperature=0.1)
            except Exception as e:
                err_msg = f"Model execution error: {e}"
                cb("error", err_msg)
                return err_msg

            if self._is_aborted:
                cb("abort", "Mission halted: Aborted by operator.")
                return "[MISSION TERMINATED // ABORTED BY OPERATOR]"

            # Extract Action JSON
            action_data, thought_text = _extract_action_data(response)

            # Check if model gave final answer without an action
            if "Final Answer:" in response and not action_data:
                final_answer = response.split("Final Answer:", 1)[1].strip()
                cb("finish", "Task completed.")
                self.chat_history.append({"role": "user", "content": task})
                self.chat_history.append({"role": "assistant", "content": final_answer})
                return final_answer

            if not action_data:
                # If model didn't use Action syntax and gave no Final Answer
                if "Final Answer:" in response or step_count > 1:
                    cb("finish", "Completed.")
                    self.chat_history.append({"role": "user", "content": task})
                    self.chat_history.append({"role": "assistant", "content": response})
                    return response
                else:
                    # Nudge model on step 1 if it only output thoughts
                    working_scratchpad += f"\nThought: {response}\nObservation: Please specify an Action in the format: Action: {{\"tool\": \"<tool_name>\", \"args\": {{...}}}} or provide your Final Answer:"
                    continue

            tool_name = action_data.get("tool") or ""
            tool_args = action_data.get("args") or {}
            if not isinstance(tool_args, dict):
                tool_args = {}

            if thought_text:
                cb("thought", thought_text)

            # Check loop
            call_sig = (tool_name, json.dumps(tool_args, sort_keys=True))
            if call_sig == last_call_sig:
                consecutive_repeat += 1
            else:
                consecutive_repeat = 0
            last_call_sig = call_sig

            if consecutive_repeat >= 2:
                obs_text = "[LOOP DETECTED] You already executed this exact tool call with these arguments. Do not repeat it. Try another tool or output your Final Answer."
                working_scratchpad += f"\nThought: {thought_text}\nAction: {json.dumps(action_data)}\nObservation: {obs_text}"
                continue

            if self._is_aborted:
                cb("abort", "Mission halted: Aborted by operator.")
                return "[MISSION TERMINATED // ABORTED BY OPERATOR]"

            cb("tool_call", f"Running: {tool_name}({json.dumps(tool_args)})")
            obs = self.toolbox.execute_tool(tool_name, tool_args)

            if self._is_aborted:
                cb("abort", "Mission halted: Aborted by operator.")
                return "[MISSION TERMINATED // ABORTED BY OPERATOR]"

            cb("tool_result", f"Result: {str(obs)[:160]}...")

            obs_preview = str(obs)[:1000]
            working_scratchpad += (
                f"\nThought: {thought_text}\n"
                f"Action: {json.dumps(action_data)}\n"
                f"Observation: {obs_preview}\n"
            )
            # Prune scratchpad if too long for small local context windows
            if len(working_scratchpad) > 4000:
                working_scratchpad = "...[earlier steps truncated]...\n" + working_scratchpad[-3500:]

        # Fallback if max steps reached
        if self._is_aborted:
            cb("abort", "Mission halted: Aborted by operator.")
            return "[MISSION TERMINATED // ABORTED BY OPERATOR]"

        cb("finish", "Reached maximum investigation steps. Generating summary...")
        summary_prompt = (
            f"User Request: {task}\n{working_scratchpad}\n"
            "Provide your final answer summarizing all findings from the investigation above:"
        )
        try:
            final_resp = self.client.chat(
                [{"role": "user", "content": summary_prompt}],
                system_prompt=system,
            )
        except Exception as e:
            final_resp = f"Summary generation notice: {e}\n\nFindings gathered:\n{working_scratchpad[:2000]}"

        self.chat_history.append({"role": "user", "content": task})
        self.chat_history.append({"role": "assistant", "content": final_resp})
        return final_resp

    def generate_executive_report(self) -> str:
        """Generate a high-level executive security narrative for the Recon Report."""
        findings_summary = self.toolbox._tool_get_scan_findings()
        prompt = (
            "Based on the following scan findings and attack chains discovered during reconnaissance:\n\n"
            f"{findings_summary}\n\n"
            "Write a concise, professional Executive Security Summary and Threat Narrative for this target. "
            "Include:\n"
            "1. Overall Security Posture Assessment\n"
            "2. Primary Attack Surface & Critical Risks\n"
            "3. Plausible Real-World Attack Scenarios\n"
            "4. Priority Remediation Roadmap"
        )
        try:
            return self.client.chat([{"role": "user", "content": prompt}], temperature=0.2)
        except Exception as e:
            return f"AI report generation unavailable: {e}"

