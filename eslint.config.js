import { commonTypeScriptRules } from "@feedic/eslint-config/typescript";
import tseslint from "typescript-eslint";
import eslintConfigBiome from "eslint-config-biome";
import globals from "globals";
import feedicFlatConfig from "@feedic/eslint-config";
import { defineConfig } from "eslint/config";

export default defineConfig(
    {
        ignores: [
            "node_modules/",
            "coverage/",
            "dist/",
            "docs/",
            "jsr.json",
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
                version: ">=20.19.0",
            },
        },
        rules: {
            "unicorn/text-encoding-identifier-case": "off",
        },
    },
    {
        files: ["**/*.ts"],
        extends: [...tseslint.configs.recommended],
        languageOptions: {
            parser: tseslint.parser,
            parserOptions: {
                sourceType: "module",
                project: "./tsconfig.eslint.json",
            },
        },
        rules: {
            ...commonTypeScriptRules,
            "@typescript-eslint/explicit-function-return-type": "error",
            "@typescript-eslint/no-unnecessary-condition": "error",
        },
    },
    eslintConfigBiome,
);
