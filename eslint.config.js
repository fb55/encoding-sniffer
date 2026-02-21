import { commonTypeScriptRules } from "@feedic/eslint-config/typescript";
import tseslint from "typescript-eslint";
import eslintConfigPrettier from "eslint-config-prettier";
import globals from "globals";
import feedicFlatConfig from "@feedic/eslint-config";
import { defineConfig } from "eslint/config";

export default defineConfig(
    {
        ignores: [
            "node_modules/",
            "coverage/",
            "lib/",
            "docs/",
            "dist/",
            ".tshy/",
            "sniffer.{js,d.ts}",
        ],
    },
    ...feedicFlatConfig,
    {
        languageOptions: {
            globals: globals.node,
            ecmaVersion: 2022,
            sourceType: "module",
        },
        settings: {
            node: {
                version: ">=22.16.0",
            },
        },
        rules: {
            "unicorn/prevent-abbreviations": "off",
            "unicorn/text-encoding-identifier-case": "off",
        },
    },
    {
        files: ["**/*.ts"],
        extends: [...tseslint.configs.recommended],
        languageOptions: {
            parser: tseslint.parser,
            parserOptions: {
                projectService: true,
                tsconfigRootDir: import.meta.dirname,
            },
        },
        rules: {
            ...commonTypeScriptRules,
            "@typescript-eslint/explicit-function-return-type": "error",
            "@typescript-eslint/no-unnecessary-condition": "error",
        },
    },
    eslintConfigPrettier,
);
