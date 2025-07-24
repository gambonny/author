import * as v from "valibot"

/**
 * Attempts to validate and extract a typed value from unknown input using a Valibot schema.
 *
 * @template TSchema - A Valibot schema used for parsing and validating the input.
 * @param schema - The Valibot schema to use for validation.
 * @param input - The unknown input value to validate and extract from.
 * @returns An object indicating whether validation succeeded:
 * - If `success` is true: `output` contains the validated value, and `issues` is undefined.
 * - If `success` is false: `issues` contains flattened validation errors, and `output` is undefined.
 *
 * @example
 * const result = extract(userSchema, maybeUser)
 * if (result.success) {
 *   const user = result.output
 * } else {
 *   console.error(result.issues)
 * }
 */
export function extract<
  TSchema extends v.BaseSchema<any, any, v.BaseIssue<unknown>>,
>(
  schema: TSchema,
  input: unknown,
):
  | { success: true; output: v.InferOutput<TSchema>; issues: undefined }
  | {
      success: false
      output: undefined
      issues: ReturnType<typeof v.flatten>["nested"]
    } {
  const result = v.safeParse(schema, input)

  if (result.success) {
    return { success: true, output: result.output, issues: undefined }
  }

  return {
    success: false,
    output: undefined,
    issues: v.flatten<TSchema>(result.issues).nested,
  }
}
