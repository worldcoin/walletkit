/**
 * CJSON.ts
 * This file is used to generate cJSON code with quicktype
 * The generated code depends of https://github.com/DaveGamble/cJSON, https://github.com/joelguittet/c-list and https://github.com/joelguittet/c-hashtable
 *
 * Similarly to C++ generator, it is possible to generate a single header file or multiple header files.
 * To generate multiple header files, use the following option: --source-style multi-source
 *
 * JSON data are represented using structures, and functions in the cJSON style are created to use them.
 * To parse json data from json string use the following: struct <type> * data = cJSON_Parse<type>(<string>);
 * To get json data from cJSON object use the following: struct <type> * data = cJSON_Get<type>Value(<cjson>);
 * To get cJSON object from json data use the following: cJSON * cjson = cJSON_Create<type>(<data>);
 * To print json string from json data use the following: char * string = cJSON_Print<type>(<data>);
 * To delete json data use the following: cJSON_Delete<type>(<data>);
 *
 * TODO list for futur enhancements:
 * - Management of Class, Union and TopLevel should be mutualized to reduce code size and to permit Union and TopLevel having recursive Array/Map
 * - Types check should be added to verify unwanted inputs (for example a Number passed while a String is expected, etc)
 * - Constraints should be implemented (verification of Enum values, min/max values for Numbers and min/max length for Strings, regex)
 * - Support of pure Any type for example providing a callback from the application to handle these cases dynamically
 * See test/languages.ts for the test cases which are not implmented/checked.
 */
import { TargetLanguage } from "../TargetLanguage";
import { Type, TypeKind, ClassType, EnumType, UnionType } from "../Type";
import { Name, Namer } from "../Naming";
import { Sourcelike } from "../Source";
import { NamingStyle } from "../support/Strings";
import { ConvenienceRenderer, ForbiddenWordsInfo } from "../ConvenienceRenderer";
import { EnumOption, StringOption, Option, OptionValues } from "../RendererOptions";
import { RenderContext } from "../Renderer";
export declare const cJSONOptions: {
    typeSourceStyle: EnumOption<boolean>;
    typeIntegerSize: EnumOption<string>;
    hashtableSize: StringOption;
    addTypedefAlias: EnumOption<boolean>;
    printStyle: EnumOption<boolean>;
    typeNamingStyle: EnumOption<NamingStyle>;
    memberNamingStyle: EnumOption<NamingStyle>;
    enumeratorNamingStyle: EnumOption<NamingStyle>;
};
export declare class CJSONTargetLanguage extends TargetLanguage {
    /**
     * Constructor
     * @param displayName: display name
     * @params names: names
     * @param extension: extension of files
     */
    constructor(displayName?: string, names?: string[], extension?: string);
    /**
     * Return cJSON generator options
     * @return cJSON generator options array
     */
    protected getOptions(): Option<any>[];
    /**
     * Indicate if language support union with both number types
     * @return true
     */
    get supportsUnionsWithBothNumberTypes(): boolean;
    /**
     * Indicate if language support optional class properties
     * @return true
     */
    get supportsOptionalClassProperties(): boolean;
    /**
     * Create renderer
     * @param renderContext: render context
     * @param untypedOptionValues
     * @return cJSON renderer
     */
    protected makeRenderer(renderContext: RenderContext, untypedOptionValues: {
        [name: string]: any;
    }): CJSONRenderer;
}
export declare enum GlobalNames {
    ClassMemberConstraints = 0,
    ClassMemberConstraintException = 1,
    ValueTooLowException = 2,
    ValueTooHighException = 3,
    ValueTooShortException = 4,
    ValueTooLongException = 5,
    InvalidPatternException = 6,
    CheckConstraint = 7
}
export declare enum IncludeKind {
    ForwardDeclare = 0,
    Include = 1
}
export type IncludeRecord = {
    kind: IncludeKind | undefined;
    typeKind: TypeKind | undefined;
};
export type TypeRecord = {
    name: Name;
    type: Type;
    level: number;
    variant: boolean;
    forceInclude: boolean;
};
export type IncludeMap = Map<string, IncludeRecord>;
export type TypeCJSON = {
    cType: Sourcelike;
    optionalQualifier: string;
    cjsonType: string;
    isType: Sourcelike;
    getValue: Sourcelike;
    addToObject: Sourcelike;
    createObject: Sourcelike;
    deleteType: Sourcelike;
    items: TypeCJSON | undefined;
    isNullable: boolean;
};
export declare class CJSONRenderer extends ConvenienceRenderer {
    private readonly _options;
    private currentFilename;
    private memberNameStyle;
    private namedTypeNameStyle;
    private forbiddenGlobalNames;
    protected readonly typeIntegerSize: string;
    protected readonly hashtableSize: string;
    protected readonly typeNamingStyle: NamingStyle;
    protected readonly enumeratorNamingStyle: NamingStyle;
    /**
     * Constructor
     * @param targetLanguage: target language
     * @param renderContext: render context
     * @param _options: renderer options
     */
    constructor(targetLanguage: TargetLanguage, renderContext: RenderContext, _options: OptionValues<typeof cJSONOptions>);
    /**
     * Build forbidden names for namespace
     * @return Forbidden names for namespace
     */
    protected forbiddenNamesForGlobalNamespace(): string[];
    /**
     * Build forbidden names for enums
     * @return Forbidden names for enums
     */
    protected forbiddenForEnumCases(_enumType: EnumType, _enumName: Name): ForbiddenWordsInfo;
    /**
     * Build forbidden names for unions members
     * @return Forbidden names for unions members
     */
    protected forbiddenForUnionMembers(_u: UnionType, _unionName: Name): ForbiddenWordsInfo;
    /**
     * Build forbidden names for objects
     * @return Forbidden names for objects
     */
    protected forbiddenForObjectProperties(_c: ClassType, _className: Name): ForbiddenWordsInfo;
    /**
     * Build types member names
     * @return types member namer
     */
    protected makeNamedTypeNamer(): Namer;
    /**
     * Build object properties member names
     * @return object properties member namer
     */
    protected namerForObjectProperty(): Namer;
    /**
     * Build union member names
     * @return union member namer
     */
    protected makeUnionMemberNamer(): Namer;
    /**
     * Build enum member names
     * @return enum member namer
     */
    protected makeEnumCaseNamer(): Namer;
    /**
     * Override of super proposeUnionMemberName function
     * @param unionType: union type
     * @param unionName: union name
     * @param fieldType: field type
     * @param lookup: Lookup function
     * @return Proposed union member name
     */
    protected proposeUnionMemberName(unionType: UnionType, unionName: Name, fieldType: Type, lookup: (n: Name) => string): string;
    /**
     * Function called to emit typedef alias for a a given type
     * @param fieldType: the variable type
     * @param fieldName: name of the variable
     */
    protected emitTypdefAlias(fieldType: Type, fieldName: Name): void;
    /**
     * Function called to create header file(s)
     * @param proposedFilename: source filename provided from stdin
     */
    protected emitSourceStructure(proposedFilename: string): void;
    /**
     * Function called to create a single header file with types and generators
     * @param proposedFilename: source filename provided from stdin
     */
    protected emitSingleSourceStructure(proposedFilename: string): void;
    /**
     * Function called to create a multiple header files with types and generators
     */
    protected emitMultiSourceStructure(): void;
    /**
     * Function called to create an enum header files with types and generators
     * @param enumType: enum type
     * @param includes: Array of includes
     */
    protected emitEnum(enumType: EnumType, includes: string[]): void;
    /**
     * Function called to create enum typedef
     * @param enumType: enum type
     */
    protected emitEnumTypedef(enumType: EnumType): void;
    /**
     * Function called to create enum prototypes
     * @param enumType: enum type
     */
    protected emitEnumPrototypes(enumType: EnumType): void;
    /**
     * Function called to create enum functions
     * @param enumType: enum type
     */
    protected emitEnumFunctions(enumType: EnumType): void;
    /**
     * Function called to create a union header files with types and generators
     * @param unionType: union type
     * @param includes: Array of includes
     */
    protected emitUnion(unionType: UnionType, includes: string[]): void;
    /**
     * Function called to create union typedef
     * @param unionType: union type
     */
    protected emitUnionTypedef(unionType: UnionType): void;
    /**
     * Function called to create union prototypes
     * @param unionType: union type
     */
    protected emitUnionPrototypes(unionType: UnionType): void;
    /**
     * Function called to create union functions
     * @param unionType: union type
     */
    protected emitUnionFunctions(unionType: UnionType): void;
    /**
     * Function called to create a class header files with types and generators
     * @param classType: class type
     * @param includes: Array of includes
     */
    protected emitClass(classType: ClassType, includes: string[]): void;
    /**
     * Function called to create class typedef
     * @param classType: class type
     */
    protected emitClassTypedef(classType: ClassType): void;
    /**
     * Function called to create class prototypes
     * @param classType: class type
     */
    protected emitClassPrototypes(classType: ClassType): void;
    /**
     * Function called to create class functions
     * @param classType: class type
     */
    protected emitClassFunctions(classType: ClassType): void;
    /**
     * Function called to create a top level header files with types and generators
     * @param type: type of the top level element
     * @param className: top level class name
     * @param includes: Array of includes
     */
    protected emitTopLevel(type: Type, className: Name, includes: string[]): void;
    /**
     * Function called to create top level typedef
     * @param type: type of the top level element
     * @param className: top level class name
     */
    protected emitTopLevelTypedef(type: Type, className: Name): void;
    /**
     * Function called to create top level prototypes
     * @param type: type of the top level element
     * @param className: top level class name
     */
    protected emitTopLevelPrototypes(_type: Type, className: Name): void;
    /**
     * Function called to create top level functions
     * @param type: type of the top level element
     * @param className: top level class name
     */
    protected emitTopLevelFunctions(type: Type, className: Name): void;
    /**
     * Convert quicktype type to cJSON type
     * @param t: quicktype type
     * @param isOptional: true if the field is optional
     * @param isNullable: true if the field is nullable
     * @return cJSON type
     */
    protected quicktypeTypeToCJSON(t: Type, isOptional: boolean, isNullable?: boolean): TypeCJSON;
    /**
     * Function called to create a file
     * @param proposedFilename: source filename provided from stdin
     */
    protected startFile(proposedFilename: Sourcelike): void;
    /**
     * Function called to close current file
     */
    protected finishFile(): void;
    /**
     * Check if type need declaration before use
     * @note If returning true, canBeForwardDeclared must be declared
     * @return Always returns true
     */
    protected get needsTypeDeclarationBeforeUse(): boolean;
    /**
     * Check if type can be forward declared
     * @return true for classes, false otherwise
     */
    protected canBeForwardDeclared(type: Type): boolean;
    /**
     * Add const to wanted Sourcelike
     * @return Const Sourcelike
     */
    protected withConst(s: Sourcelike): Sourcelike;
    /**
     * Emit include line
     * @param name: filename to include
     * @pram global: true if global include, false otherwise (default)
     */
    protected emitIncludeLine(name: Sourcelike, global?: boolean): void;
    /**
     * Emit description block
     * @param lines: description block lines
     */
    protected emitDescriptionBlock(lines: Sourcelike[]): void;
    /**
     * Emit code block
     * @param line: code block line
     * @param f: callback function
     * @param withName: name of the block as string
     * @param withSemicolon: true to add semicolon at the end of the block, false otherwise
     * @param withIndent: true to indent the block (default), false otherwise
     */
    protected emitBlock(line: Sourcelike, f: () => void, withName?: string, withSemicolon?: boolean, withIndent?: boolean): void;
    /**
     * Emit includes
     * @param type: class, union or enum type
     * @param filename: current file name
     */
    protected emitIncludes(type: ClassType | UnionType | EnumType, filename: string): void;
    /**
     * Compute includes
     * @param isClassMender: true if class, false otherwise
     * @param includes: include map
     * @param propertyType: property type
     */
    protected updateIncludes(isClassMember: boolean, includes: IncludeMap, propertyType: Type): void;
    /**
     * Compute generated types
     * @param isClassMender: true if class, false otherwise
     * @param type: type
     * @return Type record array
     */
    protected generatedTypes(isClassMember: boolean, type: Type): TypeRecord[];
}
