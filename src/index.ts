// https://html.spec.whatwg.org/multipage/syntax.html#prescan-a-byte-stream-to-determine-its-encoding

const enum State {
    // Before anything starts; can be any of BOM, UTF-16 XML declarations or meta tags
    Begin,
    // Inside of a BOM
    BOM16BE,
    BOM16LE,
    BOM8,
    // XML prefix
    UTF16LE_XML_PREFIX,
    BeginLT,
    UTF16BE_XML_PREFIX,
    // Waiting for opening `<`
    BeforeTag,
    // After the opening `<`
    BeforeTagName,
    // After `</`
    BeforeCloseTagName,
    // Beginning of a comment
    CommentStart,
    // End of a comment
    CommentEnd,
    // A tag name that could be `meta`
    TagNameMeta,
    // A tag name that is not `meta`
    TagNameOther,
    // XML declaration
    XMLDeclaration,
    XMLDeclarationBeforeEncoding,
    XMLDeclarationAfterEncoding,
    XMLDeclarationBeforeValue,
    XMLDeclarationValue,
    // Anything that looks like a tag, but doesn't fit in the above categories
    WeirdTag,

    BeforeAttribute,

    /*
     * Attributes in meta tag — we compare them to our set here, and back out
     * We care about four attributes: http-equiv, content-type, content, charset
     */
    MetaAttribHttpEquiv,
    // The value has to be `content-type`
    MetaAttribHttpEquivValue,
    MetaAttribC,
    MetaAttribContent,
    MetaAttribCharset,
    // Waiting for whitespace
    MetaAttribAfterName,
    MetaContentValueQuotedBeforeEncoding,
    MetaContentValueQuotedAfterEncoding,
    MetaContentValueQuotedBeforeValue,
    MetaContentValueQuotedValueQuoted,
    MetaContentValueQuotedValueUnquoted,
    MetaContentValueUnquotedBeforeEncoding,
    MetaContentValueUnquotedBeforeValue,
    MetaContentValueUnquotedValueQuoted,
    MetaContentValueUnquotedValueUnquoted,

    AnyAttribName,
    // After the name of an attribute, before the equals sign
    AfterAttributeName,
    // After `=`
    BeforeAttributeValue,
    AttributeValueQuoted,
    AttributeValueUnquoted,
}

export enum ResultType {
    // Byte order mark
    BOM = 0,
    // User- or transport layer-defined
    PASSED = 1,
    // XML prefixes
    XML_PREFIX = 2,
    // Meta tag
    META_TAG = 3,
    // XML encoding
    XML_ENCODING = 4,
    // Default
    DEFAULT = 5,
}

const enum AttribType {
    None,
    HttpEquiv,
    Content,
    Charset,
}

const enum Chars {
    NIL = 0x00,
    TAB = 0x09,
    LF = 0x0a,
    CR = 0x0d,
    SPACE = 0x20,
    EXCLAMATION = 0x21,
    DQUOTE = 0x22,
    SQUOTE = 0x27,
    DASH = 0x2d,
    SLASH = 0x2f,
    SEMICOLON = 0x3b,
    LT = 0x3c,
    EQUALS = 0x3d,
    GT = 0x3e,
    QUESTION = 0x3f,
    UpperA = 0x41,
    UpperZ = 0x5a,
    LowerA = 0x61,
    LowerZ = 0x7a,
}

const SPACE_CHARACTERS = new Set([Chars.SPACE, Chars.LF, Chars.CR, Chars.TAB]);
const END_OF_UNQUOTED_ATTRIBUTE_VALUE = new Set([
    Chars.SPACE,
    Chars.LF,
    Chars.CR,
    Chars.TAB,
    Chars.SLASH,
    Chars.GT,
]);

function toUint8Array(str: string) {
    const arr = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        arr[i] = str.charCodeAt(i);
    }
    return arr;
}

export const STRINGS = {
    UTF8_BOM: new Uint8Array([0xef, 0xbb, 0xbf]),
    UTF16LE_BOM: new Uint8Array([0xff, 0xfe]),
    UTF16BE_BOM: new Uint8Array([0xfe, 0xff]),
    UTF16LE_XML_PREFIX: new Uint8Array([0x3c, 0x0, 0x3f, 0x0, 0x78, 0x0]),
    UTF16BE_XML_PREFIX: new Uint8Array([0x0, 0x3c, 0x0, 0x3f, 0x0, 0x78]),
    XML_DECLARATION: toUint8Array("<?xml"),
    ENCODING: toUint8Array("encoding"),
    META: toUint8Array("meta"),
    HTTP_EQUIV: toUint8Array("http-equiv"),
    CONTENT: toUint8Array("content"),
    CONTENT_TYPE: toUint8Array("content-type"),
    CHARSET: toUint8Array("charset"),
    COMMENT_START: toUint8Array("<!--"),
    COMMENT_END: toUint8Array("-->"),
};

function isAsciiAlpha(c: number) {
    return (
        (c >= Chars.UpperA && c <= Chars.UpperZ) ||
        (c >= Chars.LowerA && c <= Chars.LowerZ)
    );
}

function isQuote(c: number) {
    return c === Chars.DQUOTE || c === Chars.SQUOTE;
}

export interface SnifferOptions {
    /**
     * The maximum number of bytes to sniff.
     *
     * @default 1024
     */
    maxBytes?: number;
    /**
     * The encoding specified by the user.
     */
    userEncoding?: string;
    /**
     * The encoding specified by the transport layer.
     */
    transportLayerEncodingLabel?: string;
    /**
     * The default encoding to use.
     *
     * @default "windows-1252"
     */
    defaultEncoding?: string;
}

export class Sniffer {
    /** The maximum number of bytes to sniff. */
    readonly maxBytes: number;
    /** All buffers we have looked at. */
    buffers: Uint8Array[] = [];
    /** The index of the buffer we are currently looking at. */
    bufferIndex = 0;
    /** The offset of the last buffer. */
    offset = 0;
    /** The index within the current buffer. */
    index = 0;

    private state = State.Begin;
    private sectionIndex = 0;
    private attribType = AttribType.None;
    private gotPragma = false;
    private needsPragma: string | null = null;

    private inMetaTag = false;

    public encoding = "windows-1252";
    public resultType = ResultType.DEFAULT;

    private setResult(encoding: string, type: ResultType) {
        // TODO validate result is a valid encoding
        if (this.resultType === ResultType.DEFAULT || this.resultType > type) {
            this.encoding = encoding.trim();
            this.resultType = type;
        }
    }

    constructor({
        maxBytes = 1024,
        userEncoding,
        transportLayerEncodingLabel,
        defaultEncoding,
    }: SnifferOptions = {}) {
        this.maxBytes = maxBytes;

        if (userEncoding) {
            this.setResult(userEncoding, ResultType.PASSED);
        }
        if (transportLayerEncodingLabel) {
            this.setResult(transportLayerEncodingLabel, ResultType.PASSED);
        }

        if (defaultEncoding) {
            this.setResult(defaultEncoding, ResultType.DEFAULT);
        }
    }

    public write(buffer: Uint8Array) {
        this.buffers.push(buffer);
        this.process();
    }

    stateBegin(c: number) {
        if (c === STRINGS.UTF16BE_BOM[0]) {
            this.state = State.BOM16BE;
        } else if (c === STRINGS.UTF16LE_BOM[0]) {
            this.state = State.BOM16LE;
        } else if (c === STRINGS.UTF8_BOM[0]) {
            this.sectionIndex = 1;
            this.state = State.BOM8;
        } else if (c === Chars.NIL) {
            this.state = State.UTF16BE_XML_PREFIX;
            this.sectionIndex = 1;
        } else if (c === Chars.LT) {
            this.state = State.BeginLT;
        } else {
            this.state = State.BeforeTag;
            this.stateBeforeTag();
        }
    }

    stateBeginLT(c: number) {
        if (c === Chars.NIL) {
            this.state = State.UTF16LE_XML_PREFIX;
            this.sectionIndex = 2;
        } else if (c === Chars.QUESTION) {
            this.state = State.XMLDeclaration;
            this.sectionIndex = 2;
        } else {
            this.state = State.BeforeTagName;
            this.stateBeforeTagName(c);
        }
    }

    stateUTF16BE_XML_PREFIX(c: number) {
        // Advance position in the section
        if (this.advanceSection(STRINGS.UTF16BE_XML_PREFIX, c)) {
            if (this.sectionIndex === STRINGS.UTF16BE_XML_PREFIX.length) {
                // We have the whole prefix
                this.setResult("utf-16be", ResultType.XML_PREFIX);
            }
        } else {
            this.state = State.BeforeTag;
            this.stateBeforeTag();
        }
    }

    stateUTF16LE_XML_PREFIX(c: number) {
        // Advance position in the section
        if (this.advanceSection(STRINGS.UTF16LE_XML_PREFIX, c)) {
            if (this.sectionIndex === STRINGS.UTF16LE_XML_PREFIX.length) {
                // We have the whole prefix
                this.setResult("utf-16le", ResultType.XML_PREFIX);
            }
        } else {
            this.state = State.BeforeTag;
            this.stateBeforeTag();
        }
    }

    stateBOM16LE(c: number) {
        if (c === STRINGS.UTF16LE_BOM[1]) {
            this.setResult("utf-16le", ResultType.BOM);
        } else {
            this.state = State.BeforeTag;
            this.stateBeforeTag();
        }
    }

    stateBOM16BE(c: number) {
        if (c === STRINGS.UTF16BE_BOM[1]) {
            this.setResult("utf-16be", ResultType.BOM);
        } else {
            this.state = State.BeforeTag;
            this.stateBeforeTag();
        }
    }

    stateBOM8(c: number) {
        if (this.advanceSection(STRINGS.UTF8_BOM, c)) {
            if (this.sectionIndex === STRINGS.UTF8_BOM.length) {
                this.setResult("utf-8", ResultType.BOM);
            }
        }
    }

    stateBeforeTag() {
        const index = this.buffers[this.bufferIndex].indexOf(
            Chars.LT,
            this.index
        );

        if (index < 0) {
            // We are done with this buffer. Stay in the state and try on the next one.
            this.index = this.buffers[this.bufferIndex].length;
        } else {
            this.index = index; // Will be increased by one later.
            this.state = State.BeforeTagName;
            this.inMetaTag = false;
        }
    }

    /**
     * We have seen a `<`, and now have to figure out what to do.
     *
     * Options:
     *  - `<meta`
     *  - Any other tag
     *  - A closing tag
     *  - `<!--`
     *  - An XML declaration
     *
     */
    stateBeforeTagName(c: number) {
        if (isAsciiAlpha(c)) {
            if ((c | 0x20) === STRINGS.META[0]) {
                this.sectionIndex = 1;
                this.state = State.TagNameMeta;
            } else {
                this.state = State.TagNameOther;
            }
        } else if (c === Chars.SLASH) {
            this.state = State.BeforeCloseTagName;
        } else if (c === Chars.EXCLAMATION) {
            this.state = State.CommentStart;
            this.sectionIndex = 2;
        } else if (c === Chars.QUESTION) {
            this.state = State.WeirdTag;
        } else {
            this.state = State.BeforeTag;
            this.stateBeforeTag();
        }
    }

    stateBeforeCloseTagName(c: number) {
        if (isAsciiAlpha(c)) {
            // Switch to `TagNameOther`; the HTML spec allows attributes here as well.
            this.state = State.TagNameOther;
        } else {
            this.state = State.WeirdTag;
        }
    }

    stateCommentStart(c: number) {
        if (this.advanceSection(STRINGS.COMMENT_START, c)) {
            if (this.sectionIndex === STRINGS.COMMENT_START.length) {
                this.state = State.CommentEnd;
                // The -- of the comment start can be part of the end.
                this.sectionIndex = 2;
            }
        } else {
            this.state = State.WeirdTag;
            this.stateWeirdTag(c);
        }
    }

    stateCommentEnd(c: number) {
        if (this.advanceSection(STRINGS.COMMENT_END, c)) {
            if (this.sectionIndex === STRINGS.COMMENT_END.length) {
                this.state = State.BeforeTag;
            }
        } else if (c === Chars.DASH) {
            /*
             * If we are here, we know we expected a `>` above.
             * Set this to 2, to support many dashes before the closing `>`.
             */
            this.sectionIndex = 2;
        }
    }

    /**
     * Any section starting with `<!`, `<?`, `</`, without being a closing tag or comment.
     */
    stateWeirdTag(c: number) {
        if (c === Chars.GT) {
            this.state = State.BeforeTag;
        }
    }

    /**
     * Advances the section, ignoring upper/lower case.
     *
     * Make sure the section has left-over characters before calling.
     *
     * @returns `false` if we did not match the section.
     */
    private advanceSectionIC(section: Uint8Array, c: number): boolean {
        return this.advanceSection(section, c | 0x20);
    }

    /**
     * Advances the section.
     *
     * Make sure the section has left-over characters before calling.
     *
     * @returns `false` if we did not match the section.
     */
    private advanceSection(section: Uint8Array, c: number): boolean {
        if (section[this.sectionIndex] === c) {
            this.sectionIndex++;
            return true;
        }

        this.sectionIndex = 0;
        return false;
    }

    stateTagNameMeta(c: number) {
        if (this.sectionIndex < STRINGS.META.length) {
            if (this.advanceSectionIC(STRINGS.META, c)) {
                return;
            }
        } else if (SPACE_CHARACTERS.has(c)) {
            this.inMetaTag = true;
            this.gotPragma = false;
            this.needsPragma = null;
            this.state = State.BeforeAttribute;
            return;
        }

        this.state = State.TagNameOther;
        // Reconsume in case there is a `>`.
        this.stateTagNameOther(c);
    }

    stateTagNameOther(c: number) {
        if (SPACE_CHARACTERS.has(c)) {
            this.state = State.BeforeAttribute;
        } else if (c === Chars.GT) {
            this.state = State.BeforeTag;
        }
    }

    stateBeforeAttribute(c: number) {
        if (SPACE_CHARACTERS.has(c)) return;

        if (this.inMetaTag) {
            const lower = c | 0x20;
            if (lower === STRINGS.HTTP_EQUIV[0]) {
                this.sectionIndex = 1;
                this.state = State.MetaAttribHttpEquiv;
                return;
            } else if (lower === STRINGS.CHARSET[0]) {
                this.sectionIndex = 1;
                this.state = State.MetaAttribC;
                return;
            }
        }

        if (c === Chars.SLASH || c === Chars.GT) {
            this.state = State.BeforeTag;
        } else {
            this.state = State.AnyAttribName;
        }
    }

    private handleMetaAttrib(c: number, section: Uint8Array, type: AttribType) {
        if (this.advanceSectionIC(section, c)) {
            if (this.sectionIndex === section.length) {
                this.attribType = type;
                this.state = State.MetaAttribAfterName;
            }
        } else {
            this.state = State.AnyAttribName;
            this.stateAnyAttribName(c);
        }
    }

    stateMetaAttribHttpEquiv(c: number) {
        this.handleMetaAttrib(c, STRINGS.HTTP_EQUIV, AttribType.HttpEquiv);
    }

    stateMetaAttribC(c: number) {
        const lower = c | 0x20;
        if (lower === STRINGS.CHARSET[1]) {
            this.sectionIndex = 2;
            this.state = State.MetaAttribCharset;
        } else if (lower === STRINGS.CONTENT[1]) {
            this.sectionIndex = 2;
            this.state = State.MetaAttribContent;
        } else {
            this.state = State.AnyAttribName;
            this.stateAnyAttribName(c);
        }
    }

    stateMetaAttribCharset(c: number) {
        this.handleMetaAttrib(c, STRINGS.CHARSET, AttribType.Charset);
    }

    stateMetaAttribContent(c: number) {
        this.handleMetaAttrib(c, STRINGS.CONTENT, AttribType.Content);
    }

    stateMetaAttribAfterName(c: number) {
        if (SPACE_CHARACTERS.has(c) || c === Chars.EQUALS) {
            this.state = State.AfterAttributeName;
            this.stateAfterAttributeName(c);
        } else {
            this.state = State.AnyAttribName;
            this.stateAnyAttribName(c);
        }
    }

    stateAnyAttribName(c: number) {
        if (SPACE_CHARACTERS.has(c)) {
            this.attribType = AttribType.None;
            this.state = State.AfterAttributeName;
        } else if (c === Chars.SLASH || c === Chars.GT) {
            this.state = State.BeforeTag;
        } else if (c === Chars.EQUALS) {
            this.state = State.BeforeAttributeValue;
        }
    }

    stateAfterAttributeName(c: number) {
        if (SPACE_CHARACTERS.has(c)) return;

        if (c === Chars.EQUALS) {
            this.state = State.BeforeAttributeValue;
        } else {
            this.state = State.BeforeAttribute;
            this.stateBeforeAttribute(c);
        }
    }

    private quoteCharacter = 0;
    private attributeValue: number[] = [];

    stateBeforeAttributeValue(c: number) {
        if (SPACE_CHARACTERS.has(c)) return;

        this.attributeValue.length = 0;
        this.sectionIndex = 0;

        if (isQuote(c)) {
            this.quoteCharacter = c;
            this.state =
                this.attribType === AttribType.Content
                    ? State.MetaContentValueQuotedBeforeEncoding
                    : this.attribType === AttribType.HttpEquiv
                    ? State.MetaAttribHttpEquivValue
                    : State.AttributeValueQuoted;
        } else if (this.attribType === AttribType.Content) {
            this.state = State.MetaContentValueUnquotedBeforeEncoding;
            this.stateMetaContentValueUnquotedBeforeEncoding(c);
        } else if (this.attribType === AttribType.HttpEquiv) {
            // We use `quoteCharacter = 0` to signify that the value is unquoted.
            this.quoteCharacter = 0;
            this.sectionIndex = 0;
            this.state = State.MetaAttribHttpEquivValue;
            this.stateMetaAttribHttpEquivValue(c);
        } else {
            this.state = State.AttributeValueUnquoted;
            this.stateAttributeValueUnquoted(c);
        }
    }

    // The value has to be `content-type`
    stateMetaAttribHttpEquivValue(c: number) {
        if (this.sectionIndex === STRINGS.CONTENT_TYPE.length) {
            if (
                this.quoteCharacter === 0
                    ? END_OF_UNQUOTED_ATTRIBUTE_VALUE.has(c)
                    : c === this.quoteCharacter
            ) {
                if (this.needsPragma !== null) {
                    this.setResult(this.needsPragma, ResultType.META_TAG);
                } else {
                    this.gotPragma = true;
                }

                this.state = State.BeforeAttribute;
                return;
            }
        } else if (this.advanceSectionIC(STRINGS.CONTENT_TYPE, c)) {
            return;
        }

        if (this.quoteCharacter === 0) {
            this.state = State.AttributeValueUnquoted;
            this.stateAttributeValueUnquoted(c);
        } else {
            this.state = State.AttributeValueQuoted;
            this.stateAttributeValueQuoted(c);
        }
    }

    private handleMetaContentValue() {
        if (this.attributeValue.length === 0) return;

        const encoding = String.fromCharCode(...this.attributeValue);

        if (this.gotPragma) {
            this.setResult(encoding, ResultType.META_TAG);
        } else {
            this.needsPragma = encoding;
        }

        this.attributeValue.length = 0;
    }

    private handleAttributeValue() {
        if (this.attribType === AttribType.Charset) {
            this.setResult(
                String.fromCharCode(...this.attributeValue),
                ResultType.META_TAG
            );
        }
    }

    stateAttributeValueUnquoted(c: number) {
        if (SPACE_CHARACTERS.has(c)) {
            this.handleAttributeValue();
            this.state = State.BeforeAttribute;
        } else if (c === Chars.SLASH || c === Chars.GT) {
            this.handleAttributeValue();
            this.state = State.BeforeTag;
        } else if (this.attribType === AttribType.Charset) {
            this.attributeValue.push(c | 0x20);
        }
    }

    private findMetaContentEncoding(c: number) {
        if (this.advanceSectionIC(STRINGS.CHARSET, c)) {
            if (this.sectionIndex === STRINGS.CHARSET.length) {
                return true;
            }
        } else {
            // If we encountered another `c`, assume we started over.
            this.sectionIndex = Number(c === STRINGS.CHARSET[0]);
        }
        return false;
    }

    stateMetaContentValueUnquotedBeforeEncoding(c: number) {
        if (END_OF_UNQUOTED_ATTRIBUTE_VALUE.has(c)) {
            this.stateAttributeValueUnquoted(c);
        } else if (this.sectionIndex === STRINGS.CHARSET.length) {
            if (c === Chars.EQUALS) {
                this.state = State.MetaContentValueUnquotedBeforeValue;
            }
        } else {
            this.findMetaContentEncoding(c);
        }
    }

    stateMetaContentValueUnquotedBeforeValue(c: number) {
        if (isQuote(c)) {
            this.quoteCharacter = c;
            this.state = State.MetaContentValueUnquotedValueQuoted;
        } else if (END_OF_UNQUOTED_ATTRIBUTE_VALUE.has(c)) {
            // Can't have spaces here, as it would no longer be part of the attribute value.
            this.stateAttributeValueUnquoted(c);
        } else {
            this.state = State.MetaContentValueUnquotedValueUnquoted;
            this.stateMetaContentValueUnquotedValueUnquoted(c);
        }
    }

    stateMetaContentValueUnquotedValueQuoted(c: number) {
        if (END_OF_UNQUOTED_ATTRIBUTE_VALUE.has(c)) {
            // Quotes weren't matched, so we're done.
            this.stateAttributeValueUnquoted(c);
        } else if (c === this.quoteCharacter) {
            this.handleMetaContentValue();
            this.state = State.AttributeValueUnquoted;
        } else {
            this.attributeValue.push(c | 0x20);
        }
    }

    stateMetaContentValueUnquotedValueUnquoted(c: number) {
        if (END_OF_UNQUOTED_ATTRIBUTE_VALUE.has(c) || c === Chars.SEMICOLON) {
            this.handleMetaContentValue();
            this.state = State.AttributeValueUnquoted;
            this.stateAttributeValueUnquoted(c);
        } else {
            this.attributeValue.push(c | 0x20);
        }
    }

    stateMetaContentValueQuotedValueUnquoted(c: number) {
        if (isQuote(c) || SPACE_CHARACTERS.has(c) || c === Chars.SEMICOLON) {
            this.handleMetaContentValue();
            // We are done with the value, but might not be at the end of the attribute
            this.state = State.AttributeValueQuoted;
            this.stateAttributeValueQuoted(c);
        } else {
            this.attributeValue.push(c | 0x20);
        }
    }

    stateMetaContentValueQuotedValueQuoted(c: number) {
        if (isQuote(c)) {
            // We have reached the end of our value.

            if (c !== this.quoteCharacter) {
                // Only handle the value if inner quotes were matched.
                this.handleMetaContentValue();
            }

            this.state = State.AttributeValueQuoted;
            this.stateAttributeValueQuoted(c);
        } else {
            this.attributeValue.push(c | 0x20);
        }
    }

    stateMetaContentValueQuotedBeforeEncoding(c: number) {
        if (c === this.quoteCharacter) {
            this.stateAttributeValueQuoted(c);
        } else if (this.findMetaContentEncoding(c)) {
            this.state = State.MetaContentValueQuotedAfterEncoding;
        }
    }

    stateMetaContentValueQuotedAfterEncoding(c: number) {
        if (c === Chars.EQUALS) {
            this.state = State.MetaContentValueQuotedBeforeValue;
        } else if (!SPACE_CHARACTERS.has(c)) {
            // Look for the next encoding
            this.state = State.MetaContentValueQuotedBeforeEncoding;
            this.stateMetaContentValueQuotedBeforeEncoding(c);
        }
    }

    stateMetaContentValueQuotedBeforeValue(c: number) {
        if (c === this.quoteCharacter) {
            this.stateAttributeValueQuoted(c);
        } else if (isQuote(c)) {
            this.state = State.MetaContentValueQuotedValueQuoted;
        } else if (!SPACE_CHARACTERS.has(c)) {
            this.state = State.MetaContentValueQuotedValueUnquoted;
            this.stateMetaContentValueQuotedValueUnquoted(c);
        }
    }

    stateAttributeValueQuoted(c: number) {
        if (c === this.quoteCharacter) {
            this.handleAttributeValue();
            this.state = State.BeforeAttribute;
        } else if (this.attribType === AttribType.Charset) {
            this.attributeValue.push(c | 0x20);
        }
    }

    // Read STRINGS.XML_DECLARATION
    stateXMLDeclaration(c: number) {
        if (this.advanceSection(STRINGS.XML_DECLARATION, c)) {
            if (this.sectionIndex === STRINGS.XML_DECLARATION.length) {
                this.sectionIndex = 0;
                this.state = State.XMLDeclarationBeforeEncoding;
            }
        } else {
            this.state = State.WeirdTag;
        }
    }

    stateXMLDeclarationBeforeEncoding(c: number) {
        if (this.advanceSection(STRINGS.ENCODING, c)) {
            if (this.sectionIndex === STRINGS.ENCODING.length) {
                this.state = State.XMLDeclarationAfterEncoding;
            }
        } else if (c === Chars.GT) {
            this.state = State.BeforeTag;
        } else {
            // If we encountered another `c`, assume we started over.
            this.sectionIndex = Number(c === STRINGS.ENCODING[0]);
        }
    }

    stateXMLDeclarationAfterEncoding(c: number) {
        if (c === Chars.EQUALS) {
            this.state = State.XMLDeclarationBeforeValue;
        } else if (c > Chars.SPACE) {
            this.state = State.WeirdTag;
            this.stateWeirdTag(c);
        }
    }

    stateXMLDeclarationBeforeValue(c: number) {
        if (isQuote(c)) {
            this.attributeValue.length = 0;
            this.state = State.XMLDeclarationValue;
        } else if (c > Chars.SPACE) {
            this.state = State.WeirdTag;
            this.stateWeirdTag(c);
        }
    }

    stateXMLDeclarationValue(c: number) {
        if (isQuote(c)) {
            this.setResult(
                String.fromCharCode(...this.attributeValue),
                ResultType.XML_ENCODING
            );
            this.state = State.WeirdTag;
        } else if (c === Chars.GT) {
            this.state = State.BeforeTag;
        } else if (c <= Chars.SPACE) {
            this.state = State.WeirdTag;
        } else {
            this.attributeValue.push(c | 0x20);
        }
    }

    process() {
        while (this.offset + this.index < this.maxBytes) {
            const c = this.buffers[this.bufferIndex][this.index];

            if (this.state === State.Begin) {
                this.stateBegin(c);
            } else if (this.state === State.BOM16BE) {
                this.stateBOM16BE(c);
            } else if (this.state === State.BOM16LE) {
                this.stateBOM16LE(c);
            } else if (this.state === State.BOM8) {
                this.stateBOM8(c);
            } else if (this.state === State.UTF16LE_XML_PREFIX) {
                this.stateUTF16LE_XML_PREFIX(c);
            } else if (this.state === State.BeginLT) {
                this.stateBeginLT(c);
            } else if (this.state === State.UTF16BE_XML_PREFIX) {
                this.stateUTF16BE_XML_PREFIX(c);
            } else if (this.state === State.BeforeTag) {
                this.stateBeforeTag();
            } else if (this.state === State.BeforeTagName) {
                this.stateBeforeTagName(c);
            } else if (this.state === State.BeforeCloseTagName) {
                this.stateBeforeCloseTagName(c);
            } else if (this.state === State.CommentStart) {
                this.stateCommentStart(c);
            } else if (this.state === State.CommentEnd) {
                this.stateCommentEnd(c);
            } else if (this.state === State.TagNameMeta) {
                this.stateTagNameMeta(c);
            } else if (this.state === State.TagNameOther) {
                this.stateTagNameOther(c);
            } else if (this.state === State.XMLDeclaration) {
                this.stateXMLDeclaration(c);
            } else if (this.state === State.XMLDeclarationBeforeEncoding) {
                this.stateXMLDeclarationBeforeEncoding(c);
            } else if (this.state === State.XMLDeclarationAfterEncoding) {
                this.stateXMLDeclarationAfterEncoding(c);
            } else if (this.state === State.XMLDeclarationBeforeValue) {
                this.stateXMLDeclarationBeforeValue(c);
            } else if (this.state === State.XMLDeclarationValue) {
                this.stateXMLDeclarationValue(c);
            } else if (this.state === State.WeirdTag) {
                this.stateWeirdTag(c);
            } else if (this.state === State.BeforeAttribute) {
                this.stateBeforeAttribute(c);
            } else if (this.state === State.MetaAttribHttpEquiv) {
                this.stateMetaAttribHttpEquiv(c);
            } else if (this.state === State.MetaAttribHttpEquivValue) {
                this.stateMetaAttribHttpEquivValue(c);
            } else if (this.state === State.MetaAttribC) {
                this.stateMetaAttribC(c);
            } else if (this.state === State.MetaAttribContent) {
                this.stateMetaAttribContent(c);
            } else if (this.state === State.MetaAttribCharset) {
                this.stateMetaAttribCharset(c);
            } else if (this.state === State.MetaAttribAfterName) {
                this.stateMetaAttribAfterName(c);
            } else if (
                this.state === State.MetaContentValueQuotedBeforeEncoding
            ) {
                this.stateMetaContentValueQuotedBeforeEncoding(c);
            } else if (
                this.state === State.MetaContentValueQuotedAfterEncoding
            ) {
                this.stateMetaContentValueQuotedAfterEncoding(c);
            } else if (this.state === State.MetaContentValueQuotedBeforeValue) {
                this.stateMetaContentValueQuotedBeforeValue(c);
            } else if (this.state === State.MetaContentValueQuotedValueQuoted) {
                this.stateMetaContentValueQuotedValueQuoted(c);
            } else if (
                this.state === State.MetaContentValueQuotedValueUnquoted
            ) {
                this.stateMetaContentValueQuotedValueUnquoted(c);
            } else if (
                this.state === State.MetaContentValueUnquotedBeforeEncoding
            ) {
                this.stateMetaContentValueUnquotedBeforeEncoding(c);
            } else if (
                this.state === State.MetaContentValueUnquotedBeforeValue
            ) {
                this.stateMetaContentValueUnquotedBeforeValue(c);
            } else if (
                this.state === State.MetaContentValueUnquotedValueQuoted
            ) {
                this.stateMetaContentValueUnquotedValueQuoted(c);
            } else if (
                this.state === State.MetaContentValueUnquotedValueUnquoted
            ) {
                this.stateMetaContentValueUnquotedValueUnquoted(c);
            } else if (this.state === State.AnyAttribName) {
                this.stateAnyAttribName(c);
            } else if (this.state === State.AfterAttributeName) {
                this.stateAfterAttributeName(c);
            } else if (this.state === State.BeforeAttributeValue) {
                this.stateBeforeAttributeValue(c);
            } else if (this.state === State.AttributeValueQuoted) {
                this.stateAttributeValueQuoted(c);
            } else {
                // (this.state === State.AttributeValueUnquoted)
                this.stateAttributeValueUnquoted(c);
            }

            if (++this.index >= this.buffers[this.bufferIndex].length) {
                this.offset += this.buffers[this.bufferIndex].length;
                this.index = 0;
                if (++this.bufferIndex === this.buffers.length) {
                    return;
                }
            }
        }
    }
}
