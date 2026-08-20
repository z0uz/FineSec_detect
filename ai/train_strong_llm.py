#!/usr/bin/env python3
"""
Train Strong Security LLM (Qwen2.5-Coder-7B / DeepSeek-Coder-6.7B)
Supports Unsloth (2-5x faster training & low memory) or standard HuggingFace PEFT/TRL.
"""

import os
import sys
import torch
import argparse
from datasets import load_dataset
from transformers import TrainingArguments

DEFAULT_MODEL = "Qwen/Qwen2.5-Coder-7B-Instruct"
DATASET_PATH = "data/training_data_strong.jsonl"
OUTPUT_DIR = "./fine-sec-7b-model"

def train_with_unsloth(model_name, dataset_path, output_dir, epochs=3, batch_size=2, max_seq_length=1024):
    """Fast fine-tuning using Unsloth"""
    print(f"🚀 Initializing Unsloth fine-tuning for model: {model_name}")
    from unsloth import FastLanguageModel
    from trl import SFTTrainer
    
    # 1. Load 4-bit quantized model
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=model_name,
        max_seq_length=max_seq_length,
        load_in_4bit=True,
        dtype=None,
    )
    
    # 2. Add LoRA adapters targeting all linear modules
    model = FastLanguageModel.get_peft_model(
        model,
        r=16,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        lora_alpha=32,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
    )
    
    # 3. Load dataset
    print(f"📊 Loading dataset from {dataset_path}...")
    dataset = load_dataset("json", data_files=dataset_path, split="train")
    
    # Format messages with ChatML tokenizer template
    def formatting_prompts_func(examples):
        convs = examples["messages"]
        texts = [tokenizer.apply_chat_template(conv, tokenize=False, add_generation_prompt=False) for conv in convs]
        return {"text": texts}
        
    dataset = dataset.map(formatting_prompts_func, batched=True)
    
    # 4. Trainer setup
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        dataset_text_field="text",
        max_seq_length=max_seq_length,
        dataset_num_proc=2,
        packing=False,
        args=TrainingArguments(
            per_device_train_batch_size=batch_size,
            gradient_accumulation_steps=4,
            warmup_steps=10,
            num_train_epochs=epochs,
            learning_rate=2e-4,
            fp16=not torch.cuda.is_bf16_supported(),
            bf16=torch.cuda.is_bf16_supported(),
            logging_steps=5,
            optim="adamw_8bit",
            weight_decay=0.01,
            lr_scheduler_type="cosine",
            seed=42,
            output_dir=output_dir,
            report_to="none",
        ),
    )
    
    print("🔥 Starting Unsloth training...")
    trainer.train()
    
    # Save model and LoRA adapter
    print(f"💾 Saving model to {output_dir}...")
    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)
    print("✅ Training successfully completed!")

def train_standard_peft(model_name, dataset_path, output_dir, epochs=3, batch_size=2, max_seq_length=1024):
    """Standard HuggingFace PEFT SFTTrainer fallback"""
    print(f"⚙️ Initializing HuggingFace PEFT training for model: {model_name}")
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from trl import SFTTrainer

    # 4-bit quantization config
    quant_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
    )

    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        quantization_config=quant_config,
        device_map="auto",
        trust_remote_code=True
    )
    model = prepare_model_for_kbit_training(model)

    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM"
    )

    model = get_peft_model(model, lora_config)

    dataset = load_dataset("json", data_files=dataset_path, split="train")

    def formatting_prompts_func(examples):
        convs = examples["messages"]
        texts = [tokenizer.apply_chat_template(conv, tokenize=False, add_generation_prompt=False) for conv in convs]
        return {"text": texts}

    dataset = dataset.map(formatting_prompts_func, batched=True)

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        dataset_text_field="text",
        max_seq_length=max_seq_length,
        args=TrainingArguments(
            per_device_train_batch_size=batch_size,
            gradient_accumulation_steps=4,
            warmup_steps=10,
            num_train_epochs=epochs,
            learning_rate=2e-4,
            fp16=True,
            logging_steps=5,
            output_dir=output_dir,
            report_to="none"
        ),
    )

    print("🔥 Starting PEFT SFT training...")
    trainer.train()

    print(f"💾 Saving model to {output_dir}...")
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    print("✅ Training finished!")

def main():
    parser = argparse.ArgumentParser(description="Train Security LLM")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Base model identifier")
    parser.add_argument("--dataset", default=DATASET_PATH, help="Path to jsonl training dataset")
    parser.add_argument("--output_dir", default=OUTPUT_DIR, help="Output directory")
    parser.add_argument("--epochs", type=int, default=3, help="Epochs")
    args = parser.parse_args()

    try:
        import unsloth
        train_with_unsloth(args.model, args.dataset, args.output_dir, epochs=args.epochs)
    except ImportError:
        print("💡 Unsloth not detected. Falling back to standard PEFT SFTTrainer...")
        train_standard_peft(args.model, args.dataset, args.output_dir, epochs=args.epochs)

if __name__ == "__main__":
    main()
