"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TypeScriptZodRenderer = exports.TypeScriptZodTargetLanguage = exports.typeScriptZodOptions = void 0;
const collection_utils_1 = require("collection-utils");
const ConvenienceRenderer_1 = require("../ConvenienceRenderer");
const Naming_1 = require("../Naming");
const RendererOptions_1 = require("../RendererOptions");
const TargetLanguage_1 = require("../TargetLanguage");
const TypeUtils_1 = require("../TypeUtils");
const Acronyms_1 = require("../support/Acronyms");
const Strings_1 = require("../support/Strings");
const Support_1 = require("../support/Support");
const JavaScript_1 = require("./JavaScript");
exports.typeScriptZodOptions = {
    justSchema: new RendererOptions_1.BooleanOption("just-schema", "Schema only", false)
};
class TypeScriptZodTargetLanguage extends TargetLanguage_1.TargetLanguage {
    getOptions() {
        return [];
    }
    constructor(displayName = "TypeScript Zod", names = ["typescript-zod"], extension = "ts") {
        super(displayName, names, extension);
    }
    get stringTypeMapping() {
        const mapping = new Map();
        const dateTimeType = "date-time";
        mapping.set("date-time", dateTimeType);
        return mapping;
    }
    makeRenderer(renderContext, untypedOptionValues) {
        return new TypeScriptZodRenderer(this, renderContext, (0, RendererOptions_1.getOptionValues)(exports.typeScriptZodOptions, untypedOptionValues));
    }
}
exports.TypeScriptZodTargetLanguage = TypeScriptZodTargetLanguage;
class TypeScriptZodRenderer extends ConvenienceRenderer_1.ConvenienceRenderer {
    constructor(targetLanguage, renderContext, _options) {
        super(targetLanguage, renderContext);
        this._options = _options;
    }
    forbiddenNamesForGlobalNamespace() {
        return ["Class", "Date", "Object", "String", "Array", "JSON", "Error"];
    }
    nameStyle(original, upper) {
        const acronyms = (0, Acronyms_1.acronymStyle)(Acronyms_1.AcronymStyleOptions.Camel);
        const words = (0, Strings_1.splitIntoWords)(original);
        return (0, Strings_1.combineWords)(words, JavaScript_1.legalizeName, upper ? Strings_1.firstUpperWordStyle : Strings_1.allLowerWordStyle, Strings_1.firstUpperWordStyle, upper ? s => (0, Strings_1.capitalize)(acronyms(s)) : Strings_1.allLowerWordStyle, acronyms, "", Strings_1.isLetterOrUnderscore);
    }
    makeNamedTypeNamer() {
        return (0, Naming_1.funPrefixNamer)("types", s => this.nameStyle(s, true));
    }
    makeUnionMemberNamer() {
        return (0, Naming_1.funPrefixNamer)("properties", s => this.nameStyle(s, true));
    }
    namerForObjectProperty() {
        return (0, Naming_1.funPrefixNamer)("properties", s => this.nameStyle(s, true));
    }
    makeEnumCaseNamer() {
        return (0, Naming_1.funPrefixNamer)("enum-cases", s => this.nameStyle(s, false));
    }
    importStatement(lhs, moduleName) {
        return ["import ", lhs, " from ", moduleName, ";"];
    }
    emitImports() {
        this.ensureBlankLine();
        this.emitLine(this.importStatement("* as z", '"zod"'));
    }
    typeMapTypeForProperty(p) {
        const typeMap = this.typeMapTypeFor(p.type);
        return p.isOptional ? [typeMap, ".optional()"] : typeMap;
    }
    typeMapTypeFor(t, required = true) {
        if (["class", "object", "enum"].indexOf(t.kind) >= 0) {
            return [this.nameForNamedType(t), "Schema"];
        }
        const match = (0, TypeUtils_1.matchType)(t, _anyType => "z.any()", _nullType => "z.null()", _boolType => "z.boolean()", _integerType => "z.number()", _doubleType => "z.number()", _stringType => "z.string()", arrayType => ["z.array(", this.typeMapTypeFor(arrayType.items, false), ")"], _classType => (0, Support_1.panic)("Should already be handled."), _mapType => ["z.record(z.string(), ", this.typeMapTypeFor(_mapType.values, false), ")"], _enumType => (0, Support_1.panic)("Should already be handled."), unionType => {
            const children = Array.from(unionType.getChildren()).map((type) => this.typeMapTypeFor(type, false));
            return ["z.union([", ...(0, collection_utils_1.arrayIntercalate)(", ", children), "])"];
        }, _transformedStringType => {
            if (_transformedStringType.kind === "date-time") {
                return "z.coerce.date()";
            }
            return "z.string()";
        });
        if (required) {
            return [match];
        }
        return match;
    }
    emitObject(name, t) {
        this.ensureBlankLine();
        this.emitLine("\nexport const ", name, "Schema = ", "z.object({");
        this.indent(() => {
            this.forEachClassProperty(t, "none", (_, jsonName, property) => {
                this.emitLine(`"${(0, Strings_1.utf16StringEscape)(jsonName)}"`, ": ", this.typeMapTypeForProperty(property), ",");
            });
        });
        this.emitLine("});");
        if (!this._options.justSchema) {
            this.emitLine("export type ", name, " = z.infer<typeof ", name, "Schema>;");
        }
    }
    emitEnum(e, enumName) {
        this.ensureBlankLine();
        this.emitDescription(this.descriptionForType(e));
        this.emitLine("\nexport const ", enumName, "Schema = ", "z.enum([");
        this.indent(() => this.forEachEnumCase(e, "none", (_, jsonName) => {
            this.emitLine('"', (0, Strings_1.stringEscape)(jsonName), '",');
        }));
        this.emitLine("]);");
        if (!this._options.justSchema) {
            this.emitLine("export type ", enumName, " = z.infer<typeof ", enumName, "Schema>;");
        }
    }
    emitSchemas() {
        this.ensureBlankLine();
        this.forEachEnum("leading-and-interposing", (u, enumName) => {
            this.emitEnum(u, enumName);
        });
        const order = [];
        const mapKey = [];
        const mapValue = [];
        this.forEachObject("none", (type, name) => {
            mapKey.push(name);
            mapValue.push(this.gatherSource(() => this.emitObject(name, type)));
        });
        mapKey.forEach((_, index) => {
            // assume first
            let ordinal = 0;
            // pull out all names
            const source = mapValue[index];
            const names = source.filter(value => value);
            // must be behind all these names
            for (let i = 0; i < names.length; i++) {
                const depName = names[i];
                // find this name's ordinal, if it has already been added
                for (let j = 0; j < order.length; j++) {
                    const depIndex = order[j];
                    if (mapKey[depIndex] === depName) {
                        // this is the index of the dependency, so make sure we come after it
                        ordinal = Math.max(ordinal, depIndex + 1);
                    }
                }
            }
            // insert index
            order.splice(ordinal, 0, index);
        });
        // now emit ordered source
        order.forEach(i => this.emitGatheredSource(mapValue[i]));
    }
    emitSourceStructure() {
        if (this.leadingComments !== undefined) {
            this.emitCommentLines(this.leadingComments);
        }
        this.emitImports();
        this.emitSchemas();
    }
}
exports.TypeScriptZodRenderer = TypeScriptZodRenderer;
