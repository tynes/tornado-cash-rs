//! Witness generation for the Tornado Cash Classic withdraw circuit.
//!
//! The circuit was compiled with circom 0.0.x, whose JSON output carries the
//! witness computation as small JavaScript template functions. Rather than
//! re-implementing every circomlib gadget by hand (and risking a mismatch
//! with the trusted-setup proving key), we run those templates in an embedded
//! JavaScript engine exactly as snarkjs did.

use crate::error::{Error, Result};
use ark_bn254::Fr;
use boa_engine::{js_string, property::Attribute, Context, JsString, JsValue, Source};
use serde_json::{json, Map, Value};
use std::str::FromStr;

const WITNESS_JS: &str = include_str!("witness.js");

/// A parsed withdraw circuit, reduced to what witness generation needs.
pub struct Circuit {
    /// Compact JSON handed to the JS runtime.
    runtime_json: String,
    pub n_vars: usize,
    pub n_pub_inputs: usize,
}

impl Circuit {
    /// Parse the circom 0.0.x JSON (`tornado.json` / `withdraw.json`).
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let v: Value = serde_json::from_slice(bytes)?;
        let get = |k: &str| {
            v.get(k)
                .ok_or_else(|| Error::Circuit(format!("missing `{k}`")))
        };
        let n_vars = get("nVars")?.as_u64().unwrap_or(0) as usize;
        let n_pub_inputs = get("nPubInputs")?.as_u64().unwrap_or(0) as usize;
        let n_signals = get("nSignals")?.clone();

        let triggers: Vec<Value> = get("signals")?
            .as_array()
            .ok_or_else(|| Error::Circuit("`signals` is not an array".into()))?
            .iter()
            .map(|s| {
                s.get("triggerComponents")
                    .cloned()
                    .unwrap_or(Value::Array(vec![]))
            })
            .collect();

        let mut runtime = Map::new();
        runtime.insert("templates".into(), get("templates")?.clone());
        runtime.insert("functions".into(), get("functions")?.clone());
        runtime.insert("components".into(), get("components")?.clone());
        runtime.insert("signalName2Idx".into(), get("signalName2Idx")?.clone());
        runtime.insert("triggers".into(), Value::Array(triggers));
        runtime.insert("nVars".into(), json!(n_vars));
        runtime.insert("nSignals".into(), n_signals);

        Ok(Circuit {
            runtime_json: serde_json::to_string(&runtime)?,
            n_vars,
            n_pub_inputs,
        })
    }

    /// Compute the full witness (`nVars` field elements, starting with the
    /// constant `1`) for the given named inputs. Each input is either a
    /// decimal string or an array of decimal strings.
    pub fn calculate_witness(&self, inputs: &Value) -> Result<Vec<Fr>> {
        // Component triggering recurses once per nested sub-component, which
        // goes far deeper than boa's defaults allow. Run on a thread with a
        // large native stack and lift the interpreter's limits.
        let inputs = inputs.to_string();
        std::thread::scope(|s| {
            std::thread::Builder::new()
                .stack_size(1 << 30)
                .spawn_scoped(s, || self.calculate_witness_inner(&inputs))
                .map_err(|e| Error::Witness(e.to_string()))?
                .join()
                .map_err(|_| Error::Witness("witness thread panicked".into()))?
        })
    }

    fn calculate_witness_inner(&self, inputs: &str) -> Result<Vec<Fr>> {
        let mut ctx = Context::default();
        ctx.runtime_limits_mut().set_recursion_limit(usize::MAX);
        ctx.runtime_limits_mut().set_stack_size_limit(usize::MAX);
        let attr = Attribute::all();
        ctx.register_global_property(
            js_string!("__CIRCUIT_JSON"),
            JsValue::from(JsString::from(self.runtime_json.as_str())),
            attr,
        )
        .map_err(js_err)?;
        ctx.register_global_property(
            js_string!("__INPUT_JSON"),
            JsValue::from(JsString::from(inputs)),
            attr,
        )
        .map_err(js_err)?;
        ctx.eval(Source::from_bytes(WITNESS_JS)).map_err(js_err)?;
        let out = ctx
            .eval(Source::from_bytes(
                "calculateWitness(JSON.parse(__CIRCUIT_JSON), JSON.parse(__INPUT_JSON))",
            ))
            .map_err(js_err)?;
        let s = out
            .as_string()
            .ok_or_else(|| Error::Witness("witness calculator returned a non-string".into()))?
            .to_std_string_escaped();
        let w: Vec<Fr> = s
            .split(',')
            .map(|x| Fr::from_str(x).map_err(|_| Error::Witness(format!("bad witness value {x}"))))
            .collect::<Result<_>>()?;
        if w.len() != self.n_vars {
            return Err(Error::Witness(format!(
                "expected {} values, got {}",
                self.n_vars,
                w.len()
            )));
        }
        Ok(w)
    }
}

fn js_err(e: boa_engine::JsError) -> Error {
    Error::Witness(e.to_string())
}
