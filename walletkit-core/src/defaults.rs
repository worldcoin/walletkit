use alloy_primitives::{address, Address};
use world_id_core::{primitives::Config, AuthenticatorConfig, OhttpClientConfig};

use crate::{error::WalletKitError, Environment, Region};

/// The World ID Registry contract address on World Chain Mainnet.
pub static WORLD_ID_REGISTRY: Address =
    address!("0x0000000000aE079eB8a274cD51c0f44a9E4d67d4");

/// The **Staging** World ID Registry contract address also on World Chain Mainnet.
pub static STAGING_WORLD_ID_REGISTRY: Address =
    address!("0x8556d07D75025f286fe757C7EeEceC40D54FA16D");

/// The `PoH` Recovery Agent contract address on the staging environment.
pub static POH_RECOVERY_AGENT_ADDRESS_STAGING: Address =
    address!("0x8df366ed8ef894f0d1d25dc21b7e36e2d97a7140");

/// The `PoH` Recovery Agent contract address on the production environment.
pub static POH_RECOVERY_AGENT_ADDRESS_PRODUCTION: Address =
    address!("0x00000000CBBA8Cb46C8CD414B62213F1B334fC59");

pub(crate) fn poh_recovery_agent_address(environment: &Environment) -> Address {
    match environment {
        Environment::Staging => POH_RECOVERY_AGENT_ADDRESS_STAGING,
        Environment::Production => POH_RECOVERY_AGENT_ADDRESS_PRODUCTION,
    }
}

const OPRF_NODE_COUNT: usize = 5;

/// Generates the list of OPRF node URLs for a given region and environment.
fn oprf_node_urls(region: Region, environment: &Environment) -> Vec<String> {
    let env_segment = match environment {
        Environment::Staging => ".staging",
        Environment::Production => "",
    };

    (0..OPRF_NODE_COUNT)
        .map(|i| {
            format!("https://node{i}.{region}{env_segment}.world.oprf.taceo.network")
        })
        .collect()
}

fn indexer_url(region: Region, environment: &Environment) -> String {
    let domain = match environment {
        Environment::Staging => "worldcoin.dev",
        Environment::Production => "world.org",
    };
    format!("https://indexer.{region}.id-infra.{domain}")
}

/// Build a [`Config`] from well-known defaults for a given [`Environment`].
pub trait DefaultConfig {
    /// Returns a config populated with the default URLs and addresses for the given environment.
    ///
    /// # Errors
    ///
    /// Returns [`WalletKitError`] if the configuration cannot be constructed (e.g. invalid RPC URL).
    fn from_environment(
        environment: &Environment,
        rpc_url: Option<String>,
        region: Option<Region>,
    ) -> Result<Self, WalletKitError>
    where
        Self: Sized;
}

fn ohttp_relay_url(region: Region, environment: &Environment) -> String {
    let path = match environment {
        Environment::Staging => format!("{region}-world-id-stage"),
        Environment::Production => format!("{region}-world-id"),
    };
    let host = match environment {
        Environment::Staging => "staging.privacy-relay.cloudflare.com",
        Environment::Production => "privacy-relay.cloudflare.com",
    };
    format!("https://{host}/{path}")
}

// Base64-encoded `application/ohttp-keys` payloads fetched from /ohttp-keys endpoints.
// Each region has an independent HPKE key derived from its own seed secret.
// To refresh, fetch from: ohttp-keys.{us,eu,ap}.id-infra.{worldcoin.dev,world.org}/ohttp-keys
const OHTTP_KEY_CONFIG_STAGING_US: &str = "BMkAADA6CsGxhCbqsMqylxxajRYYsf4Dl48gicxg4IH6/6VeCjTYb5iRhuJSZZq7DE5JKqLjwIO8wnVIHUZikTKIb1RjwPeEtZFMdrXcoX/EALimBZ2oinX1Om0JRN9XORX2NCLmBU2SFteQNr3ohT5CkJ3VUXcMOG3cjzthS65zOUFmfi3IdSBqGgz4po0KigmDKNW8zPU5jKozsxk0hXECKFJnJbzDqYXWf/YmSPtLRtEcVn8haLngTwcnMRMTmSgSXQ/DbIv3MQh4HP74e6rWmoHmcEW6HSkWrnJFvTw4Wh+jmIw1hYsADviWPyEbWDiazteiRRgJrENDAsdTZ/DSF4A8LfM7XMulS7Boc+BwVOoSaljxPfokda2jZIIwfIVSi+hMIxT8W4bnGvv1b01XNxWVOspAPWpWa/0Zn6yZVF6RFI2bu4m2J4LoZ8lSfXC5H81Diq75A/l0tfsRi9vCbKiIau1Relg4cPKDFW8beDbpHOyUJE72T0PBNulKQdibeVBKcn5wqzYThCu5aMGis5P7OO6hwbiHQuHFjV/UcwMGv0KYKhVBjm3BTbNQJsUseRZEPlUgIyHsd2/2okBbS5xWip9oGmwqJy0Iur1JA7JFEQepvNmQCgkQOZRFMbaQI6rykQsKyvbBfpU4BMWiyHMXZas8buKVCEtQLymZjfLrbnLxhXTRrhBQE0sVNnOCg5p1adfSGTiSPb38NQyZpy0bs4mTum7IzViUpxx4fsj2V2LFZZC5vTWCUzuzEVrhXYYaNKWJZbRIn8WGfAGVees2CRg1RaMwI2jWnlqwcCtpZzNkIVYScm/hWXF5tlO6eYdZbNIjNoRlX/VTPzDEly4Jg6XgOJfpFsiYLH/JgehhfzRIrh57fdIUew80CwqnxDkiy687Abz3lm10sJyTUGzXKPV0t/9hqjM1G9yUMJSVdd2pID6YXf2kM+qEPpVCFy3oHYuVGs9rF+UxPb8iw4NLuVQLov3YMS5ZhciFdoQ1ZRxbzUSZUjh4Ox93SJWpS+y7EtaEcxIrOjlAsuGYt4xDB2iVMVJErDuBZHCzhAbcHNjzV8KzAW45eeeTtBYoHSZaXSFbrc8sgsFlhQcRf+SKcgGzdOt2gX6Ej1dmgEz3Si8QC7drMOOmHctWk8hRch7wqJ5RT1sAWwVBynelmflqzcSXXyU8Uoq2tinRcLzZLmUoVHhDo77xa4emI3/WEBUyRwABiBlHJwxrYkDxXJRgXW76xzShVQBqxTQzV1XJLPu4olFCRbrBw05GbZnjgQOcG8fXjDTxKHEcqJH6AkUlPdGhe7t8vbeKlQ4biudmC1GcarpYjkjRO2JkiMg4x4UApGukKSV8uFCrj/Vwtr4UQOv6yIjzFLNaKzZAd168fQZYKDNoTH/FsFWKyc+bKcOjDf8wk2opc1XkGvAChg03U0DRCAblaG4AAOdFvPRaa6umSvzDbDBCbHlkS5IQgYH8TzpAP0egyI45w8s1tV+AM/PhXcr2v3jWjlJTD4nxNI0ysyQEYKzmP3z7PSP4Zg9bBZ2hPVF0wMMAd5J0rqCiUAGTpwGMpbr6S5h5PQ04IiuQejhcWgqTbR3JfEdyH8OAY+MevUaL5usPqAb0rQdCAAQAAQABACmAACAhTDtqOkZY35ljpAi0prs+klopmTMUxP86XxVJSaZoTgAEAAEAAQ==";
const OHTTP_KEY_CONFIG_STAGING_EU: &str = "BMkAADAk4SzO30gcPPW5V914Fq8OTXKDIHVlQL6Ki76lXxu9Qu8UO5FjGzu5JR7Ly8M1ICH4tgy4Zqsoqrx6wJTRKF/giGgTeXA3tmipMyoChAbTiNdwDHgHRumCMUpqNUGobg+7pgIsxYnENxm3dEhBvFpWySN3D0GwaJ0WeIkxz220FY/3ekb5ql7ZV4PhnhW8StMmGDyRWSV5yllsncemyN9qlQHzEJq6tawKSOH1R04jw5JSNqWsuODLGNrBoftphG6ToiWZQjU8wpBJAcdhkLOEPzyCGjLJubVHYiYVf8b5nccpYeXIYSjnzxG7mNy2Qq8gCjXQTVIICHo8QFc1cS2VORyAVxYQp5CEu2bRclP1TD55NiDDQgQSdVYRhyCcMv6Aiq1MBdfRo8paMq71ehTMWRsaQR9WCMF8SHesPxtmbbhBVa/CxeKbnU3Gw40ljlz2IHGGlrZ0R8rMlNGnAsv1K9l3k4RDf40TFXWscDM1eT+FbB0EKPviruyAiRZho+FSgfk5X1PopyhWxwqkNGVUeN4UrK5DMDrVBBTYiRXDddg8PoVGek7lDQsXjkWku7kKVZDavrFgzZJDG+31EM05bMrpZ3moW+3hpF2BrIYTaIIRyToIoWa2rexWe8ZpTMMhU5IbMqvxtt4jzFW0GGFUHhVHDBNcnJy5DQgpxh/zyb/0R9NjPVbxDwuEuY/RHnAHqCMHcxlcv/9nM//3wHfCOhzHA+XJMrj1BClAM2HYba7glEpyRgXogi/TWFPrC+v8Cig1C7vEG42yk05okhtWKrRUD7RLEDOUOKjFIq0bc3yamSwHZZrwE2dbWwbotYgnwJzccXP8lSziNts5WnXUPKS1eTBJbJ0qhqpXaqCAO6v1lQx6JMfGmLGiWpwRSGJXI9A6LeNDV0AQhH8iI544TkUnY8QHVn+AUtWGezGGSK0yNEM6ngzDOO8EzvGBLXjwKJ+6hCOMuIryN8j7oR/ZOoXaKg0rApu1e+6AClknRnsoBzMGMLT3gQHAPHcmGSWgL5sxW5PGPDhEhhumoudzZpLne/WXRoL2GawxiBdDzoFEgs3DhGqBECd4PUI5UwqLMMkIcL6ohl7Bf3NcZHdYBi/0C01kJ0pLIfoRphBUFt53hdlMvr2xM3Iij884t/9CfslQsuMrpwlsahlHPz33mJfxzt4KNSz5qA8QERd1xbPlgVqVxoeHTg/ZNcEHAQB2N2gib+GSxCTKAssCZQFUjILXfHOXmyCKaOcckM6cEldIKX62SjtJIakLYLnIp1lRUJQrD8bjgtaHYw6wmqY3VC1AhdgsFjEEcWmhF1QyDeu4vjMXkJ2kTRwClExEVqIFjmD3kKTbWeWQd53SiAByFGBUz92yzD6DE93ZEltDUyVADVqbNbNETKGRnGlqL5KBqabyFqVIKw8BMNhQE5qwlnNkxoCJCDQlb4ObLJ85uuX5maMVzO4qlkh2H0GZS9+Gat5EI7uIivjUxjVUmbAjHriTfyMiCaoUQ/3oyv2xIsthbMgEHqV4cxVqGuATHYeQhnCHbz4ZE8lrWMfkBqSiUWyLyrezsKP7paCXBP9HqptMAWQhS55ajQgJNeHvNAojYrzHsoLKJdbC0wMIUgW8AAQAAQABACmAACDpvMa1g5bJ7CN2pI+ohQ0JBAjlaeFR6kxA2tQW7ulmNgAEAAEAAQ==";
const OHTTP_KEY_CONFIG_STAGING_AP: &str = "BMkAADDld5RcqfGv74Xi5GklZlg6EVP2+5K05bRrJXEO3kj9dAKFUaSYSc30To7aYCFMJGA5n+9zlOyRWKtXf8BcWNO0BSFzgeW6SEWCOuQGLrU6c4EWJUVGwAKmoxLFCp35HvSaIzxKpdkHrttFIXfwyKchZn0Vcvo5ggBsMF9Uz2xokqLWBhXwqnZ7AC0kox12MfCnIqmDxfzEGL35itdnoyqTf8BhjFiFS32TZ3S1ZTH2i+xMHqGiCZ0Ych7pbGMprQO2emCTaTQwEG2WqTrzFkmwsOfnd7crsi/JBq+5h3OYaWR0Ij9BpaU5nzVcHzvcqY1ntAyqsf8ak82Gd+EwDNPCBmdsXKPVVY5URrhQpjcxLIn7gnYGF+qLHHmFy6DkrIyKs4sXBJApOQHqeKkxEdlKSvrxRHvrHycccIl0mlNbpgZ6QlVAAhl0TczXUTyyLVzxdrURHoVcCjGYJoVLH2FQmDKhY8vKGK1LZv3ycfxacDt2DSTys1QwtkwrXacbITRjFo+aWxT6GIOKFYQ5I7v4aSlTzdREauSltDOXPZV7bihnLz56AAPnapMXX3KAiMx6dK8IOavVjTVFCoAhhh0JxYfCvv/KVpxorz3qduviTpvrqZ0HqoWrh5iRHK+TL1rHWMlkzAmCYEx0JJrJhckQRvJTnA6HwUiJlq4cgmZ5YDpSZrcqi+SWahuJhcqwNa9nAf0CkGpDu8/ltSGFATWqNvkFEXKpQFFIkXwSIgyXGYzwBkBJDLOhqTnUhKN6x4hwidiaCIi4w+2zn8lHnokAU4lFTuVJMOnUZVx6FVA4UpwQPi8ngLoXtRSJffPQahPICHBEyadjcMICJeL0Ap/MpPbTyieWnCYWa487rN1BP44TuZ0krZIkOkzVbl6ym2aVeVuQGPNspTKaGrIHb6LndgdVCuezK4EEYWaniLBkOuv7WJ60JoT3wzMqkfQ4dSWnFehkGRasbzn4uNEZpwApq8xFluwAh/okModnxN63T7/IZjDchhUIasQixl6aqAIBGrVbpbl8wMTMrFsWVAdqjJdMfhW4JLhAZurhjs92HVaRYy8ZvyrbrDDYZy0xf/C6gnAgSKZ4ZOBTVqlqAIaWBr8VJx6SmwBElPM7l+MJWs+AGwb1EZJ4PWnDkpqVq7ajrpaWsz0IVT5ak8VEg/SCBRzhyjEqCrTLHulFF50Xw6HSMsE0ddhobZNbhkQJbZcbNqqSgw4QvNkMGcbWM3TZlziYzwSXkBqZJCXcrlPGTS8YpA0JKvIrozBxHehAl6wIpwMyvFTWIy+AtrfVBhXgxIU0PHc4Yrz4sHuKSaJCAoxSLzYbciP3zbT1f6cSli6obrosmx/Uos9gBwIyHwRZRGKoCar3NtxGQFJmZgxCbgy2mnGxDgIYxIuzcfLhCIpriJ8xiknJH6dTkGGKbiCUlIOiRu9Fig66coYWcve7rsJkIgELxeIHBZ3TD0NKpJpTFmiRpisgvAOABIIjyZhAspSMtbQAeKYWa+23gr8LrLBJLXowElWDWfLMKH7WIIw2a2yVyE9UmtxRdGFouugIB/X6R8OQN1cYa3/cslBAjwHBoQr3Vq/o+XhJYNnXF9O3jrXR0hsGf0izlKHbRXmiAAQAAQABACmAACDY6Zn2xioLKlGQUAa2gATjAqM+Q1tFk/quYO2BB56fJAAEAAEAAQ==";
const OHTTP_KEY_CONFIG_PRODUCTION_US: &str = "BMkAADD0uZYGrGJrPD0w7gJVqpT1XhjXxI3gaUzG31JsKF/afaNEkR8oJsBykJMot71cGnQLQzRYoOZ3M8O7zybpnoZxMi04N3tRJW7gl1IMuUP1ZH7MH5B6QFbVhm4UXYJwderiF1tlRtE1iKoVjR65CQYWyE0VrVIgJCBIgAcTLtlAe/ZHP+VMnrgwlDWRn+yFlSZjQ6w5DZ53Cdz0GEDJv86DuU6gFhQLRFnChiYWWZpIFIaXnYiJKPL6qQ3brMr6G6qoUpPVfFXyuzyIUwKUYOU5T561AWxmv1EctpeDBtNzuSXQZQBYLcvaRrCEzO0Kr3WDNclLbw8xqwUWAIpzSfvFbsW7n2WhwWs4GVuWy2NUInQbIlqJQwbzGEGSkmmHoRz6XRm8oRHBauwqlTjqzysAurERhEF8TbIgtnqgPnwbqPrGZ9TFvpAon7oJO80ZuxZmF9JcAMx8H//nariGqsSQvckWVmEBLzsFsUW5B2x2AEAqqDFmtQm5Oja2wL6AzeH8UfNweIhluEDLR6npJANxjRAIBp+GG/HguAKAX5DAYuuGuCsVhJrhu/vSRVCZIW8hoj6QGBzLVdGwZr8rQmQJFxuKCEdJEnXbnfcqqbj6AcBYGGnhfs9anL2CPmtLCShZF9rKGHwhorcBRhZBn1m4OwCtrGzoDMclpur2OIhURZ4yr5IoFcdIdwYExNKoDHAqikNjAYeouad5SUMqe4k0cNZhVziJdV7FCe5XG1OzjbZbmiKEtgxFnSayw1wwJ7b4ycFMWSeZRIGXU6cBGM7Lmkc5Pn3rRsLYK9HwFHJwn82Io2vDpWm6AoELRwKZyD2jJZx5kfzZTKWmOPactcbBcTLQRXJGFKmnDqorhtzhYfGqFlVntPK2Xj3HT3NwUnOGR00EClbYzSVzlRThAXkpuQw3YaxwCHyUeWY0XTbQcOtBW73QU2zGbDFEL2lYDDXil6YjuDDkx67DuS3rFT95pLy4qUUIILYLQC+KBnKaJ0dEw1ZHjVuqXzK8pxI2iL9KLc6Uf6ZAXAa1Y5pTLLkJjSZ0i4OgmBFbeal1pkE6dKv3TAdCBgTBXtS0yaOiMrVUJ/kzrYbINedUh+unkpYlDOh7sgxctN1wdmdyhaj2skukAJU0S1astRlpeAP3vhPLjAUVaaAVHEAyygvbuMuJCD/6U5BTrbsnKgwxPjUrWB0pMEcGxvUWKbgqNMibPhPoK1rXhqugaQwgcJlSzaqRR8J6WZqmgyspBzhWei8aqpz3TTSETuo8TcORpS05ZEbVKAbKOumpD0W5bPcsHr/oEgCtbIfJpDNTWgbFUXjAZX93R54Zk5iyU1WoEyyInw4EKaZioEeTXj0SXjxhkP3LQjCYkYzGQow2LBn8lLu4YYPmk536hq8Fhizci501HX86sLhHPwKCfPCBKtNcVWCTO7skSSWpuBI4mic6i+lMjRUKn0akDs6yKDi3WkPUmIOWIz6QmNQqIrmaOnWXHFfXqoslq5W5YmKjnpUoZ4OYOYBbsu+KP6eHWIbGs8h0uq26i31mjoKYK3RHnkMBN+VQNtEAOicxhBxCMtRMw1xDT2dk0Z26dF3ntmf1rPL+RSHxE3PggM//b+af8WpSBRtlAAQAAQABACmAACDhiLcA4Ws+aDLvutFOrQZV42qWKGKCYSuOhpBOrhYGbQAEAAEAAQ==";
const OHTTP_KEY_CONFIG_PRODUCTION_EU: &str = "BMkAADCJj2MDlX4h8jJ2W1FGgTZELWc4zYADW6CGxdaiIpfjR5/JF8EgDwLSI37YK4fDZBAxz8H5FojBdUj4K0saYc/FUqlEqUyIsXpJLSvFsnLlHp28TzAjrjdDr2zgCPqyT7+AGtx2C8xKEAbwxZ3xtq/aMY3md/NIpxmFsKBlk4slaqFjDNgzF7InM7zhQKjzRLlmEFwEGXn0wH35wIWYXhXQCSXDJDyVjVlzesIVOxPpj2rEFweHgN1ocEVhe0aluVJacp05q5sIGFfMRS6YY9Yyoe/Fj2caQWxjHk9mm6/oD/k5AR4Zlv6GdG6yx/mZJm6LB4sSins7fZEsKVcbaCQgj4txzxAStYiZNogHFF6YrhazYlXYkytDilgMNlSxOg3HPXXEax4CJZdCHD9rHBR4wPOrfA9aK4iylPNFX1ViKLsXNuy2Z6nEH6Zwx/yKQlDseXUat26AIYkht9anVUWQKeqkFW2RcyeBmKxLVJOAZ9z2sae5yLfnX3rZd1GAn6DBF9yzC5SGJAdHTPK3OBEXXW2BHwDzsj47L58hoXO5tLEXiX6Dj46LpYRaok9rAr61lWpKn2Tmz/LCzyXGAqBzlplCLfj3HPtcp/G7v9uTsZ28bdfKvniwVvvVAJCAT4wKr/wbwY4Mjr+TcP0BQDwbcm87tl+4EbVrYfHLZu5FouRWfwdUQS+8eX8zu0FHS3zpicZym8WBnV1EFSmUaUmMcVQ7pE9wGOiMvkbixC/io9jsqwOJxTNqVJohOkvad7x2naDFrs0wC8+wbtZWFWcSSJQ2QsESVHY3ANHnczrhi7iJCiPCftyzLEjLJVBbtcvnRubLsseQpT4WZz+ZJdT0Lfuaa6+SvMJzqQ/ctLlCTCGmTvtTKCQbvsAAKNY3mcy8dXnQGuASu3OsCMncBg5TtUEhIuvVjvKKaqDRsRcyo4FTVsBxfPqXa6JjE4XIwKrIK5KRS2tmoap1ocxAjd7lXVCgIJLDX9O6r2fnZfokCt+BG0oLxbKjkl6waIrUf73TyaBhLCcqlS0BHRVHzYYWUxRkGQ4VMg53U571O475KwMSNMTiMffkl+pFVBc3e5mVbr+bXuZzUgKhg8YlKM/5Tfvzpk0kfvPDpFvAvN3bCieIQeJ3peX8nWhjpBaKO/8hZ34GaCU0JP8AffdFLS95gag7UBrFfVRSg//7JVTxFPViLComR6xkKUirMA2GsQEjPHPkqDhadN2bzx3qgRBbdegIOBZxQCsAMpjpl6ljTGUhWK/YfedVAGD0aEGjBd1Cg2gjLy2YnOw5XTiUmnP0nI5BmogSU9qZbcGpIM2XrlPAvW7hAH5kWjWIcXyDt2niCjTVDBESxL8mLY9sLmk0bhJjb7tsS+LyJ2zQoZRFvD/DuRV8QHa1xtNJpC96YHtctR02XAlxg29AlxZDYi3qiTo0G/D8ouAHGNplEpT4jctoLdySQSwlcvokEzd3t+hyYzaqP2xiyOjTqwTIwpUSy3y7r21ggdDBDv8WFvBjG/sbqv84m5Sqr1jSJXuwi4lDXEqCgbA7PN0km7SByn3FgCW7Emr2Ma37E+bwH9EhNg95Mw30ZPL3oz4PQrvRAHfrotaXo4yajwZSzfvnMVc7AAQAAQABACmAACC1zCaczRhTvo2BugVHLUV+BmsJ/m1JAnCN4Fp7xgfYawAEAAEAAQ==";
const OHTTP_KEY_CONFIG_PRODUCTION_AP: &str = "BMkAADCbLx4cxxrpkY9mdZ+hBKcrkZelRyisL/iqLuhZqX2dJSdALk0MIYUkpzIchtOWsmEntuehBBmKoANjOcVodgvWuLLlhljrsY8nG/ADNq/3uBjntuiXtdw1ZuX4IxnUtnBATScIqQhoClTbgloAgaRpAI1Ierh7eKrEl+YLOPilrXYxBhupXI26ZCIDyhLrP/g4C1TsQcyaFN4rTzwCzyPBQRSUyMDTXe6BOpqXcwsDKDKsxySTlj1yFUtWrbtAm3SbcTPlEWqTVnfHyZl1HxtTJTe5C2D0GUaLa2pMC/CHc9rsWKipUejEAZJAqcrrV5fJdkwhHsySLpCbwxynf2OaS7mScW17ASEXf7UTkq0Jk5zVYEnklcWap414i+AXnPNyb/pIZZPCgprICo1jh+qsPM5EzMegotj8UR41VrfDWQMFlxU5xrWpAR8wBTUJgIwVto+oksZ0hTBQBsalpq0rmdEjwryaIjuXA9RKNoWCuAW0bNBCtkvlVEBmjWazEh93yBb6Ix0bqHKpD8lEfeJ4B/0cguwYljbyUMsgl5fXhL3oMbwiOkIlcia7BXjsDerrwSPEYDWRTWtXsIWyKiEsCNM6Sp34F5BEy2qYKNFrvmr3Cm/lUJ3TfKhnwqAASoEwxCP1VwallrXTKTmon2CcmdKMDV0ZZ8oUheLCFNqsMcKmZ5b4QkO4jdUly8sYIDZYyqyFQuSDxZ93GaEDILU4ubbDyCjwy/gIrz3koZcTE8CEvBFwXHHpFtoWKpEwMZlog9CbeMUJUOSwkjTwDuXRPMnKBo3WtDiRwhEitUahwzq4a3AakbA5s9TzEAZhXaUsQ+pnkYV0PeziB2pKA0owZI8Zp7KGMgs7DRZGZEEWeQgRrXUYP79ArPSjnj5kzODsjX9XN9KcchKAw2tSMJzbNHF5Rf8XyIE8TeUVHArJqAB0kcL1kokUM8b7CQjqt1ZjAolIn91XxAirEqhbWWsaxL3DU+1FmGc8M0qGUUjRlslaYqVKj26AjlcyEbBBmvpcf/gitdE7BHAiItIEHNf1Cw+BhcRjWTaZw1crWyP7gEp8Ln9bEfr6ZLIgnmVYsn2TXeJXW57XvrSAU+hLztiSRDObqEz8nC2wHankqM2hbnNpuuglNH04NG7nVgBLcR4YjzJBWSk1ih+CdhpJOyf0qJV1ES41SRSsAQFofaX7KEIYQSUpoPDRoIdqtxdhcKuqm95aJpy4UDEylzARkkzBNKHCRvVxGePIjPpkcBSndkboPFLAvFmGqzqCxfc2MZ87LmFaPOeJvElpjqITB9s7kvQjwqC0d5mKExsziVBzmrzYon5prDCVD0uxwcKGKzBskvwhEy1Gnpo6pAOAYXwTW5wWBP1jwXjBuVe2LVkXMmdHUO22oFgby+Z5u7DYspI8xqO3OvFgw2v5T/wxRZI5msvznpDQf9j5Mw+UhTUKcf96VFglm0nMzndmPgmGaJHcUzViP4awnkejf9FDoz+6hA9jKIwoT3i6hXApr3LbJTiFiNxjCpvWg7m6eGdkiwA6fGOTLLT0f8u5s0LyJiWjVrRoLPkgCWzDzVRyQT2XDvIonKEy6QpX5UIOzkzpZw2V7JlQCSgklzmpm6BmxnlqAAQAAQABACmAACAk5NGXEPAmZucRpaXLXVXkzbpjnRIvwCZMFjqpyTtZeAAEAAEAAQ==";

const fn ohttp_key_config(region: Region, environment: &Environment) -> &'static str {
    match (environment, region) {
        (Environment::Staging, Region::Us) => OHTTP_KEY_CONFIG_STAGING_US,
        (Environment::Staging, Region::Eu) => OHTTP_KEY_CONFIG_STAGING_EU,
        (Environment::Staging, Region::Ap) => OHTTP_KEY_CONFIG_STAGING_AP,
        (Environment::Production, Region::Us) => OHTTP_KEY_CONFIG_PRODUCTION_US,
        (Environment::Production, Region::Eu) => OHTTP_KEY_CONFIG_PRODUCTION_EU,
        (Environment::Production, Region::Ap) => OHTTP_KEY_CONFIG_PRODUCTION_AP,
    }
}

impl DefaultConfig for AuthenticatorConfig {
    fn from_environment(
        environment: &Environment,
        rpc_url: Option<String>,
        region: Option<Region>,
    ) -> Result<Self, WalletKitError> {
        let region = region.unwrap_or_default();
        let config = Config::from_environment(environment, rpc_url, Some(region))?;

        let key_config_base64 = ohttp_key_config(region, environment);
        let relay_url = ohttp_relay_url(region, environment);
        let ohttp = Some(OhttpClientConfig::new(
            relay_url,
            key_config_base64.to_string(),
        ));

        Ok(Self {
            config,
            ohttp_indexer: ohttp.clone(),
            ohttp_gateway: ohttp,
        })
    }
}

impl DefaultConfig for Config {
    fn from_environment(
        environment: &Environment,
        rpc_url: Option<String>,
        region: Option<Region>,
    ) -> Result<Self, WalletKitError> {
        let region = region.unwrap_or_default();

        match environment {
            Environment::Staging => Self::new(
                rpc_url,
                480, // Staging also runs on World Chain Mainnet
                STAGING_WORLD_ID_REGISTRY,
                indexer_url(region, environment),
                "https://gateway.id-infra.worldcoin.dev".to_string(),
                oprf_node_urls(region, environment),
                3,
            )
            .map_err(WalletKitError::from),

            Environment::Production => Self::new(
                rpc_url,
                480,
                WORLD_ID_REGISTRY,
                indexer_url(region, environment),
                "https://gateway.id-infra.world.org".to_string(),
                oprf_node_urls(region, environment),
                3,
            )
            .map_err(WalletKitError::from),
        }
    }
}
