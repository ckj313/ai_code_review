from typing import Sequence


def _format_bullet_list(items: Sequence[str]) -> str:
    return "\n".join(f"   - {item}" for item in items)


def _format_numbered_list(items: Sequence[str]) -> str:
    return "\n".join(f"{i}. {item}" for i, item in enumerate(items, start=1))


def build_initial_analysis_prompt(vuln_display_names: Sequence[str]) -> str:
    vuln_list = _format_bullet_list(vuln_display_names)
    return INITIAL_ANALYSIS_PROMPT_TEMPLATE.format(vuln_list=vuln_list)


def build_system_prompt(vuln_display_names: Sequence[str]) -> str:
    vuln_list = _format_numbered_list(vuln_display_names)
    return SYS_PROMPT_TEMPLATE.format(vuln_list=vuln_list)


INITIAL_ANALYSIS_PROMPT_TEMPLATE = """
请对白盒代码进行问题排查，关注代码缺陷或合规问题：
1. 识别可疑的问题入口或代码路径，必要时通过 <context_code> 请求补齐上下文。
2. 优先结合以下问题类型进行排查：
{vuln_list}
3. 标注需要进一步上下文的位置。

不需要输出 PoC 或漏洞利用，只需指出问题位置和调用链。
"""

README_SUMMARY_PROMPT_TEMPLATE = """
请从白盒代码检查视角，对 <readme_content></readme_content> 的 README 做简要摘要，关注：
1. 项目用途与核心模块
2. 可能影响代码检查的关键功能或组件
3. 与配置、日志或资源管理相关的特性

输出 <summary></summary> XML 标签，使用中文。
"""

GUIDELINES_TEMPLATE = """报告要求：
1. JSON 格式：
   - 输出一个完整的 JSON 报告，符合 <response_format> 的 schema。
   - 如果信息不足，使用 "None"。

2. 上下文请求：
   - 类名：ClassName1,ClassName2
   - 函数：func_name,ClassName.method_name
   - 如果已请求 ClassName，不要再请求 ClassName.method_name。
   - 不要请求标准库或第三方库代码。

3. 问题范围：
   - 仅针对 <skill_id> 与 <candidate_matches> 提供的范围。
   - 不做漏洞利用分析，不输出 PoC。
   - 必须给出问题行号与调用栈。

4. 语言：
   - 所有字段使用中文。
"""

ANALYSIS_APPROACH_TEMPLATE = """分析指引：
1. 白盒检查视角：
   - 重点找代码缺陷或合规问题，不做漏洞利用分析。

2. 问题定位：
   - 使用 <candidate_matches> 作为起点。
   - 参考 <positive_example> 和 <negative_example> 降低误报。
   - 提供问题行号与调用栈。

3. 上下文补齐：
   - 如果需要更多上下文，使用 <context_code> 请求。
   - 不要请求标准库或第三方库代码。

4. 输出：
   - 输出中文 JSON，符合 <response_format> schema。
"""

SYS_PROMPT_TEMPLATE = """
你是进行白盒检查的工程师，任务是静态审查 C 代码中的缺陷与合规问题，重点包括但不限于：

{vuln_list}

要求：
- 以代码质量与合规为目标，不做漏洞利用分析。
- 必须给出问题行号与调用栈。
- 不完整的调用链需要在 <context_code> 中请求补齐。

README 摘要在 <readme_summary> 中，仅作为项目背景参考。

输出必须是 JSON，并符合 <response_format> schema，使用中文。
"""
