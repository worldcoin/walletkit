"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SmithyTargetLanguage = exports.Smithy4sRenderer = exports.SmithyOptions = exports.Framework = void 0;
const Annotation_1 = require("../Annotation");
const ConvenienceRenderer_1 = require("../ConvenienceRenderer");
const Naming_1 = require("../Naming");
const RendererOptions_1 = require("../RendererOptions");
const Source_1 = require("../Source");
const Strings_1 = require("../support/Strings");
const Support_1 = require("../support/Support");
const TargetLanguage_1 = require("../TargetLanguage");
const Type_1 = require("../Type");
const TypeUtils_1 = require("../TypeUtils");
var Framework;
(function (Framework) {
    Framework[Framework["None"] = 0] = "None";
})(Framework = exports.Framework || (exports.Framework = {}));
exports.SmithyOptions = {
    framework: new RendererOptions_1.EnumOption("framework", "Serialization framework", [
        ["just-types", Framework.None]
    ], undefined),
    packageName: new RendererOptions_1.StringOption("package", "Package", "PACKAGE", "quicktype")
};
// Use backticks for param names with symbols
const invalidSymbols = [
    ":",
    "-",
    "+",
    "!",
    "@",
    "#",
    "%",
    "^",
    "&",
    "*",
    "(",
    ")",
    ">",
    "<",
    "/",
    ";",
    "'",
    '"',
    "{",
    "}",
    ":",
    "~",
    "`",
    "."
];
const keywords = [
    "abstract",
    "case",
    "catch",
    "do",
    "else",
    "export",
    "false",
    "final",
    "finally",
    "for",
    "forSome",
    "if",
    "implicit",
    "import",
    "new",
    "override",
    "package",
    "private",
    "protected",
    "return",
    "sealed",
    "super",
    "this",
    "then",
    "throw",
    "trait",
    "try",
    "true",
    "val",
    "var",
    "while",
    "with",
    "yield",
    "Any",
    "Boolean",
    "Double",
    "Float",
    "Long",
    "Int",
    "Short",
    "System",
    "Byte",
    "String",
    "Array",
    "List",
    "Map",
    "Enum"
];
/**
 * Check if given parameter name should be wrapped in a backtick
 * @param paramName
 */
const shouldAddBacktick = (paramName) => {
    return keywords.some(s => paramName === s) || invalidSymbols.some(s => paramName.includes(s)) || !isNaN(parseFloat(paramName)) || !isNaN(parseInt(paramName.charAt(0)));
};
function isPartCharacter(codePoint) {
    return (0, Strings_1.isLetterOrUnderscore)(codePoint) || (0, Strings_1.isNumeric)(codePoint);
}
function isStartCharacter(codePoint) {
    return isPartCharacter(codePoint) && !(0, Strings_1.isDigit)(codePoint);
}
const legalizeName = (0, Strings_1.legalizeCharacters)(isPartCharacter);
function scalaNameStyle(isUpper, original) {
    const words = (0, Strings_1.splitIntoWords)(original);
    return (0, Strings_1.combineWords)(words, legalizeName, isUpper ? Strings_1.firstUpperWordStyle : Strings_1.allLowerWordStyle, Strings_1.firstUpperWordStyle, isUpper ? Strings_1.allUpperWordStyle : Strings_1.allLowerWordStyle, Strings_1.allUpperWordStyle, "", isStartCharacter);
}
const upperNamingFunction = (0, Naming_1.funPrefixNamer)("upper", s => scalaNameStyle(true, s));
const lowerNamingFunction = (0, Naming_1.funPrefixNamer)("lower", s => scalaNameStyle(false, s));
class Smithy4sRenderer extends ConvenienceRenderer_1.ConvenienceRenderer {
    constructor(targetLanguage, renderContext, _scalaOptions) {
        super(targetLanguage, renderContext);
        this._scalaOptions = _scalaOptions;
    }
    forbiddenNamesForGlobalNamespace() {
        return keywords;
    }
    forbiddenForObjectProperties(_, _classNamed) {
        return { names: [], includeGlobalForbidden: true };
    }
    forbiddenForEnumCases(_, _enumName) {
        return { names: [], includeGlobalForbidden: true };
    }
    forbiddenForUnionMembers(_u, _unionName) {
        return { names: [], includeGlobalForbidden: false };
    }
    topLevelNameStyle(rawName) {
        return scalaNameStyle(true, rawName);
    }
    makeNamedTypeNamer() {
        return upperNamingFunction;
    }
    namerForObjectProperty() {
        return lowerNamingFunction;
    }
    makeUnionMemberNamer() {
        return (0, Naming_1.funPrefixNamer)("upper", s => scalaNameStyle(true, s) + "Value");
    }
    makeEnumCaseNamer() {
        return (0, Naming_1.funPrefixNamer)("upper", s => s.replace(" ", "")); // TODO - add backticks where appropriate
    }
    emitDescriptionBlock(lines) {
        this.emitCommentLines(lines, " * ", "/**", " */");
    }
    emitBlock(line, f, delimiter = "curly") {
        const [open, close] = delimiter === "curly"
            ? ["{", "}"]
            : delimiter === "paren"
                ? ["(", ")"]
                : delimiter === "none"
                    ? ["", ""]
                    : ["{", "})"];
        this.emitLine(line, " ", open);
        this.indent(f);
        this.emitLine(close);
    }
    anySourceType(_) {
        return ["Document"];
    }
    // (asarazan): I've broken out the following two functions
    // because some renderers, such as kotlinx, can cope with `any`, while some get mad.
    arrayType(arrayType, _ = false) {
        //this.emitTopLevelArray(arrayType, new Name(arrayType.getCombinedName().toString() + "List"))
        return arrayType.getCombinedName().toString() + "List";
    }
    emitArrayType(_, smithyType) {
        this.emitLine(["list ", smithyType, " { member : ", "}"]);
    }
    mapType(mapType, _ = false) {
        return mapType.getCombinedName().toString() + "Map";
        //return [this.scalaType(mapType.values, withIssues), "Map"];
    }
    scalaType(t, withIssues = false, noOptional = false) {
        return (0, TypeUtils_1.matchType)(t, _anyType => {
            return (0, Source_1.maybeAnnotated)(withIssues, Annotation_1.anyTypeIssueAnnotation, this.anySourceType(!noOptional));
        }, _nullType => {
            //return "None.type"
            return (0, Source_1.maybeAnnotated)(withIssues, Annotation_1.nullTypeIssueAnnotation, this.anySourceType(!noOptional));
        }, _boolType => "Boolean", _integerType => "Long", _doubleType => "Double", _stringType => "String", arrayType => this.arrayType(arrayType, withIssues), classType => this.nameForNamedType(classType), mapType => this.mapType(mapType, withIssues), enumType => this.nameForNamedType(enumType), unionType => {
            const nullable = (0, TypeUtils_1.nullableFromUnion)(unionType);
            if (nullable !== null) {
                return [this.scalaType(nullable, withIssues)];
            }
            return this.nameForNamedType(unionType);
        });
    }
    emitUsageHeader() {
        // To be overridden
    }
    emitHeader() {
        if (this.leadingComments !== undefined) {
            this.emitCommentLines(this.leadingComments);
        }
        else {
            this.emitUsageHeader();
        }
        this.ensureBlankLine();
        this.emitLine("$version: \"2\"");
        this.emitLine("namespace ", this._scalaOptions.packageName);
        this.ensureBlankLine();
        this.emitLine("document NullValue");
        this.ensureBlankLine();
    }
    emitTopLevelArray(t, name) {
        const elementType = this.scalaType(t.items);
        this.emitLine(["list ", name, " { member : ", elementType, "}"]);
    }
    emitTopLevelMap(t, name) {
        const elementType = this.scalaType(t.values);
        this.emitLine(["map ", name, " { map[ key : String , value : ", elementType, "}"]);
    }
    emitEmptyClassDefinition(c, className) {
        this.emitDescription(this.descriptionForType(c));
        this.emitLine("structure ", className, "{}");
    }
    emitClassDefinition(c, className) {
        if (c.getProperties().size === 0) {
            this.emitEmptyClassDefinition(c, className);
            return;
        }
        const scalaType = (p) => {
            if (p.isOptional) {
                return [this.scalaType(p.type, true, true)];
            }
            else {
                return [this.scalaType(p.type, true)];
            }
        };
        const emitLater = [];
        this.emitDescription(this.descriptionForType(c));
        this.emitLine("structure ", className, " {");
        this.indent(() => {
            let count = c.getProperties().size;
            let first = true;
            this.forEachClassProperty(c, "none", (_, jsonName, p) => {
                const nullable = p.type.kind === "union" && (0, TypeUtils_1.nullableFromUnion)(p.type) !== null;
                const nullableOrOptional = p.isOptional || p.type.kind === "null" || nullable;
                const last = --count === 0;
                const meta = [];
                const laterType = p.type.kind === "array" || p.type.kind === "map";
                if (laterType) {
                    emitLater.push(p);
                }
                const description = this.descriptionForClassProperty(c, jsonName);
                if (description !== undefined) {
                    meta.push(() => this.emitDescription(description));
                }
                if (meta.length > 0 && !first) {
                    this.ensureBlankLine();
                }
                for (const emit of meta) {
                    emit();
                }
                const nameNeedsBackticks = jsonName.endsWith("_") || shouldAddBacktick(jsonName);
                const nameWithBackticks = nameNeedsBackticks ? "`" + jsonName + "`" : jsonName;
                this.emitLine(p.isOptional ? "" : nullableOrOptional ? "" : "@required ", nameWithBackticks, " : ", scalaType(p), last ? "" : ",");
                if (meta.length > 0 && !last) {
                    this.ensureBlankLine();
                }
                first = false;
            });
        });
        this.emitClassDefinitionMethods(emitLater);
    }
    emitClassDefinitionMethods(arrayTypes) {
        this.emitLine("}");
        arrayTypes.forEach(p => {
            function ignore(_) {
                return;
            }
            (0, TypeUtils_1.matchCompoundType)(p.type, at => {
                this.emitLine(["list ", this.scalaType(at, true), "{ member: ", this.scalaType(at.items, true), "}"]);
            }, ignore, mt => {
                this.emitLine(["map ", this.scalaType(mt, true), "{ key: String , value: ", this.scalaType(mt.values, true), "}"]);
            }, ignore, ignore);
        });
    }
    emitEnumDefinition(e, enumName) {
        this.emitDescription(this.descriptionForType(e));
        this.ensureBlankLine();
        this.emitItem(["enum ", enumName, " { "]);
        let count = e.cases.size;
        this.forEachEnumCase(e, "none", (name, jsonName) => {
            // if (!(jsonName == "")) { 
            /*                 const backticks =
                                shouldAddBacktick(jsonName) ||
                                jsonName.includes(" ") ||
                                !isNaN(parseInt(jsonName.charAt(0)))
                            if (backticks) {this.emitItem("`")} else  */
            this.emitLine();
            this.emitItem([name, " = \"", jsonName, "\""]);
            //                if (backticks) {this.emitItem("`")}
            if (--count > 0)
                this.emitItem([","]);
            //} else {
            //--count
            //} 
        });
        this.ensureBlankLine();
        this.emitItem(["}"]);
    }
    emitUnionDefinition(u, unionName) {
        function sortBy(t) {
            const kind = t.kind;
            if (kind === "class")
                return kind;
            return "_" + kind;
        }
        const emitLater = [];
        this.emitDescription(this.descriptionForType(u));
        const [maybeNull, nonNulls] = (0, TypeUtils_1.removeNullFromUnion)(u, sortBy);
        const theTypes = [];
        this.forEachUnionMember(u, nonNulls, "none", null, (_, t) => {
            const laterType = t.kind === "array" || t.kind === "map";
            if (laterType) {
                emitLater.push(t);
            }
            theTypes.push(this.scalaType(t));
        });
        if (maybeNull !== null) {
            theTypes.push(this.nameForUnionMember(u, maybeNull));
        }
        this.emitLine(["@untagged union ", unionName, " { "]);
        this.indent(() => {
            theTypes.forEach((t, i) => {
                this.emitLine([String.fromCharCode(i + 65), " : ", t]);
            });
        });
        this.emitLine("}");
        this.ensureBlankLine();
        emitLater.forEach(p => {
            function ignore(_) {
                return;
            }
            (0, TypeUtils_1.matchCompoundType)(p, at => {
                this.emitLine(["list ", this.scalaType(at, true), "{ member: ", this.scalaType(at.items, true), "}"]);
            }, ignore, mt => {
                this.emitLine(["map ", this.scalaType(mt, true), "{ key: String , value: ", this.scalaType(mt.values, true), "}"]);
            }, ignore, ignore);
        });
    }
    emitSourceStructure() {
        this.emitHeader();
        // Top-level arrays, maps
        this.forEachTopLevel("leading", (t, name) => {
            if (t instanceof Type_1.ArrayType) {
                this.emitTopLevelArray(t, name);
            }
            else if (t instanceof Type_1.MapType) {
                this.emitTopLevelMap(t, name);
            }
        });
        this.forEachNamedType("leading-and-interposing", (c, n) => this.emitClassDefinition(c, n), (e, n) => this.emitEnumDefinition(e, n), (u, n) => this.emitUnionDefinition(u, n));
    }
}
exports.Smithy4sRenderer = Smithy4sRenderer;
class SmithyTargetLanguage extends TargetLanguage_1.TargetLanguage {
    constructor() {
        super("Smithy", ["Smithy"], "smithy");
    }
    getOptions() {
        return [exports.SmithyOptions.framework, exports.SmithyOptions.packageName];
    }
    get supportsOptionalClassProperties() {
        return true;
    }
    get supportsUnionsWithBothNumberTypes() {
        return true;
    }
    makeRenderer(renderContext, untypedOptionValues) {
        const options = (0, RendererOptions_1.getOptionValues)(exports.SmithyOptions, untypedOptionValues);
        switch (options.framework) {
            case Framework.None:
                return new Smithy4sRenderer(this, renderContext, options);
            default:
                return (0, Support_1.assertNever)(options.framework);
        }
    }
}
exports.SmithyTargetLanguage = SmithyTargetLanguage;
