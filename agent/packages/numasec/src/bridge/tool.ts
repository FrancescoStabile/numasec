import z from "zod"
import { Tool } from "../tool/tool"
import { PythonBridge } from "./python"

/**
 * Create a Tool.Info that delegates to a Python bridge method.
 *
 * @param id - Tool identifier
 * @param description - Tool description shown to the LLM
 * @param parameters - Zod schema for the tool's parameters
 * @param formatResult - Optional function to format the result for display
 */
export function bridgeTool<T extends z.ZodType>(
  id: string,
  description: string,
  parameters: T,
  formatResult?: (result: any) => string,
): Tool.Info<T> {
  return Tool.define(id, {
    description,
    parameters,
    async execute(args, ctx) {
      const bridge = PythonBridge.instance()
      const result = await bridge.call(id, args as Record<string, any>)

      const output = formatResult
        ? formatResult(result)
        : typeof result === "string"
          ? result
          : JSON.stringify(result, null, 2)

      return {
        title: id,
        output,
        metadata: {},
      }
    },
  })
}
