import { ConvenienceRenderer, ForbiddenWordsInfo } from "../ConvenienceRenderer";
import { Name, Namer } from "../Naming";
import { EnumOption, Option, StringOption, OptionValues } from "../RendererOptions";
import { Sourcelike } from "../Source";
import { TargetLanguage } from "../TargetLanguage";
import { ArrayType, ClassProperty, ClassType, EnumType, MapType, ObjectType, Type, UnionType } from "../Type";
import { RenderContext } from "../Renderer";
export declare enum Framework {
    None = 0
}
export declare const SmithyOptions: {
    framework: EnumOption<Framework>;
    packageName: StringOption;
};
export declare class Smithy4sRenderer extends ConvenienceRenderer {
    protected readonly _scalaOptions: OptionValues<typeof SmithyOptions>;
    constructor(targetLanguage: TargetLanguage, renderContext: RenderContext, _scalaOptions: OptionValues<typeof SmithyOptions>);
    protected forbiddenNamesForGlobalNamespace(): string[];
    protected forbiddenForObjectProperties(_: ObjectType, _classNamed: Name): ForbiddenWordsInfo;
    protected forbiddenForEnumCases(_: EnumType, _enumName: Name): ForbiddenWordsInfo;
    protected forbiddenForUnionMembers(_u: UnionType, _unionName: Name): ForbiddenWordsInfo;
    protected topLevelNameStyle(rawName: string): string;
    protected makeNamedTypeNamer(): Namer;
    protected namerForObjectProperty(): Namer;
    protected makeUnionMemberNamer(): Namer;
    protected makeEnumCaseNamer(): Namer;
    protected emitDescriptionBlock(lines: Sourcelike[]): void;
    protected emitBlock(line: Sourcelike, f: () => void, delimiter?: "curly" | "paren" | "lambda" | "none"): void;
    protected anySourceType(_: boolean): Sourcelike;
    protected arrayType(arrayType: ArrayType, _?: boolean): Sourcelike;
    protected emitArrayType(_: ArrayType, smithyType: Sourcelike): void;
    protected mapType(mapType: MapType, _?: boolean): Sourcelike;
    protected scalaType(t: Type, withIssues?: boolean, noOptional?: boolean): Sourcelike;
    protected emitUsageHeader(): void;
    protected emitHeader(): void;
    protected emitTopLevelArray(t: ArrayType, name: Name): void;
    protected emitTopLevelMap(t: MapType, name: Name): void;
    protected emitEmptyClassDefinition(c: ClassType, className: Name): void;
    protected emitClassDefinition(c: ClassType, className: Name): void;
    protected emitClassDefinitionMethods(arrayTypes: ClassProperty[]): void;
    protected emitEnumDefinition(e: EnumType, enumName: Name): void;
    protected emitUnionDefinition(u: UnionType, unionName: Name): void;
    protected emitSourceStructure(): void;
}
export declare class SmithyTargetLanguage extends TargetLanguage {
    constructor();
    protected getOptions(): Option<any>[];
    get supportsOptionalClassProperties(): boolean;
    get supportsUnionsWithBothNumberTypes(): boolean;
    protected makeRenderer(renderContext: RenderContext, untypedOptionValues: {
        [name: string]: any;
    }): ConvenienceRenderer;
}
