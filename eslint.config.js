import eslint from "@eslint/js";
import tseslint from "typescript-eslint";
import unicorn from "eslint-plugin-unicorn";
import nodePlugin from "eslint-plugin-n";
import eslintConfigPrettier from "eslint-config-prettier";
import globals from "globals";

export default tseslint.config(
    {
        ignores: ["node_modules/", "coverage/", "docs/", "dist/"],
    },
    eslint.configs.recommended,
    unicorn.configs.recommended,
    nodePlugin.configs["flat/recommended"],
    {
        languageOptions: {
            globals: {
                ...globals.node,
            },
            ecmaVersion: 2022,
            sourceType: "module",
        },
        settings: {
            node: {
                version: ">=20.11.0",
            },
        },
        rules: {
            eqeqeq: ["error", "smart"],
            "no-caller": "error",
            "dot-notation": "error",
            "no-var": "error",
            "prefer-const": "error",
            "prefer-arrow-callback": ["error", { allowNamedFunctions: true }],
            "arrow-body-style": ["error", "as-needed"],
            "object-shorthand": "error",
            "prefer-template": "error",
            "one-var": ["error", "never"],
            "prefer-destructuring": ["error", { object: true }],
            "capitalized-comments": "error",
            "multiline-comment-style": ["error", "starred-block"],
            "spaced-comment": "error",
            yoda: ["error", "never"],
            curly: ["error", "multi-line"],
            "no-else-return": "error",

            "unicorn/no-null": "off",
            "unicorn/prevent-abbreviations": "off",
            "unicorn/prefer-code-point": "off",
            "unicorn/text-encoding-identifier-case": "off",
            "unicorn/prefer-module": "off",
            "unicorn/prefer-switch": [
                "error",
                { emptyDefaultCase: "do-nothing-comment" },
            ],
        },
    },
    {
        files: ["**/*.ts"],
        extends: [...tseslint.configs.recommended],
        languageOptions: {
            parserOptions: {
                projectService: true,
                tsconfigRootDir: import.meta.dirname,
            },
        },
        rules: {
            "@typescript-eslint/prefer-for-of": "off",
            "@typescript-eslint/member-ordering": "off",
            "@typescript-eslint/explicit-function-return-type": "error",
            "@typescript-eslint/no-use-before-define": [
                "error",
                { functions: false },
            ],
            "@typescript-eslint/consistent-type-definitions": [
                "error",
                "interface",
            ],
            "@typescript-eslint/prefer-function-type": "error",
            "@typescript-eslint/no-unnecessary-type-arguments": "error",
            "@typescript-eslint/prefer-string-starts-ends-with": "error",
            "@typescript-eslint/prefer-readonly": "error",
            "@typescript-eslint/prefer-includes": "error",
            "@typescript-eslint/no-unnecessary-condition": "error",
            "@typescript-eslint/switch-exhaustiveness-check": "error",
            "@typescript-eslint/prefer-nullish-coalescing": "error",
        },
    },
    eslintConfigPrettier,
);
