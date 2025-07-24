import * as v from "valibot"

export type TypedSchema = v.BaseSchema<any, any, v.BaseIssue<unknown>>
export type OnValidationError = (
  issues: ReturnType<typeof v.flatten>["nested"],
) => void

export type ExtractResult<TSchema extends TypedSchema> =
  | { success: true; output: v.InferOutput<TSchema>; issues: undefined }
  | {
      success: false
      output: undefined
      issues: ReturnType<typeof v.flatten>["nested"]
    }

export function extract<TSchema extends TypedSchema>(schema: TSchema) {
  return {
    from(
      input: unknown,
      onValidationError?: OnValidationError,
    ): ExtractResult<TSchema> {
      const result = v.safeParse(schema, input)

      if (result.success) {
        return { success: true, output: result.output, issues: undefined }
      }

      const flattened = v.flatten(result.issues).nested
      onValidationError?.(flattened)

      return {
        success: false,
        output: undefined,
        issues: flattened,
      }
    },

    safe(
      input: unknown,
      onValidationError?: OnValidationError,
    ): ReturnType<typeof v.safeParse> {
      const result = v.safeParse(schema, input)

      if (!result.success) {
        onValidationError?.(v.flatten(result.issues).nested)
      }

      return result
    },

    parse(input: unknown): v.InferOutput<TSchema> {
      return v.parse(schema, input)
    },
  }
}
