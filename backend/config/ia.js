import OpenAI from "openai";
import { GoogleGenerativeAI } from "@google/generative-ai";


// =============================
// OPENAI
// =============================

export let openaiClient = null;


if (process.env.OPENAI_API_KEY) {

    openaiClient = new OpenAI({
        apiKey: process.env.OPENAI_API_KEY
    });


    console.log("🔑 OpenAI configurado");

} else {

    console.log("⚠️ OPENAI_API_KEY no encontrada");

}



// =============================
// GEMINI
// =============================

export let geminiModel = null;


if(process.env.GEMINI_API_KEY){

    try{

        const genAI =
        new GoogleGenerativeAI(
            process.env.GEMINI_API_KEY
        );


        geminiModel =
        genAI.getGenerativeModel({
            model:"gemini-2.5-flash"
        });


        console.log(
            "✅ Gemini configurado"
        );


    }catch(error){

        console.error(
            "❌ Error Gemini:",
            error.message
        );

    }


}else{

    console.log(
        "⚠️ GEMINI_API_KEY no encontrada"
    );

}



// =============================
// PROVEEDOR ACTUAL
// =============================

export const IA_PROVIDER =
process.env.IA_PROVIDER || "gemini";