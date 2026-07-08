#!/usr/bin/env python3
"""
Data preparation script for glibc vulnerability testing
"""

import pandas as pd
import json
import random
import os
from pathlib import Path

class GlibcDataProcessor:
    def __init__(self, csv_path="data/dump-glibc.csv"):
        self.csv_path = csv_path
        self.df = None
        self.test_samples = None
    
    def load_dataset(self):
        """Load and analyze the glibc dataset"""
        print("🔄 Loading glibc dataset...")
        
        self.df = pd.read_csv(self.csv_path)
        
        # Basic analysis
        print(f"📊 Dataset Overview:")
        print(f"   Total records: {len(self.df)}")
        print(f"   Unique CVEs: {self.df['CVE'].nunique()}")
        print(f"   Vulnerability types:")
        
        vuln_types = self.df['V_CLASSIFICATION'].value_counts().head(10)
        for vtype, count in vuln_types.items():
            print(f"      {vtype}: {count}")
        
        return self.df
    
    def create_test_samples(self, n_samples=25):
        """Create representative test samples"""
        print(f"\n🎯 Creating {n_samples} test samples...")
        
        # Get different vulnerability types
        vuln_types = self.df['V_CLASSIFICATION'].unique()
        test_samples = []
        
        # Ensure variety in vulnerability types
        samples_per_type = max(1, n_samples // min(len(vuln_types), 8))
        
        for vuln_type in vuln_types[:8]:  # Top 8 types
            type_samples = self.df[self.df['V_CLASSIFICATION'] == vuln_type]
            if len(type_samples) > 0:
                sample_count = min(samples_per_type, len(type_samples))
                selected = type_samples.sample(n=sample_count, random_state=42)
                test_samples.append(selected)
        
        self.test_samples = pd.concat(test_samples).reset_index(drop=True)
        
        # If we need more samples, add random ones
        if len(self.test_samples) < n_samples:
            remaining = n_samples - len(self.test_samples)
            additional = self.df.sample(n=remaining, random_state=42)
            self.test_samples = pd.concat([self.test_samples, additional]).drop_duplicates().reset_index(drop=True)
        
        # Trim to exact number
        self.test_samples = self.test_samples.head(n_samples)
        
        print(f"✅ Created {len(self.test_samples)} test samples")
        return self.test_samples
    
    def create_vulnerability_prompts(self):
        """Create prompts for vulnerability detection testing"""
        print("\n📝 Creating vulnerability detection prompts...")
        
        prompts = []
        
        for idx, row in self.test_samples.iterrows():
            # Create comprehensive prompt for vulnerability detection
            prompt_data = {
                'id': idx + 1,
                'cve_id': row['CVE'],
                'file_path': row['FilePath'],
                'vulnerability_classification': row['V_CLASSIFICATION'],
                'vulnerability_url': row['VULNERABILITY_URL'],
                'commit_hash': row['P_COMMIT'],
                'prompt_basic': f"""Analyze this file path for potential security vulnerabilities:

File: {row['FilePath']}
Context: This is from the glibc C library.

Please identify:
1. Potential vulnerability types
2. Risk level (Critical/High/Medium/Low)
3. Brief explanation of the security concern
4. Recommended mitigation approach

Respond in a structured format.""",

                'prompt_detailed': f"""You are a security expert analyzing source code for vulnerabilities.

Target File: {row['FilePath']}
Library: GNU C Library (glibc)
Context: This file has been associated with security issues.

Please provide a comprehensive security analysis:

1. **Vulnerability Assessment**:
   - What types of security vulnerabilities might exist in this file?
   - What is the potential impact? (Code execution, DoS, Information disclosure, etc.)

2. **Risk Evaluation**:
   - Risk Level: Critical/High/Medium/Low
   - Exploitability: Easy/Moderate/Difficult
   - Impact Scope: Local/Remote/Network

3. **Technical Analysis**:
   - Common vulnerability patterns for this type of file
   - Potential attack vectors
   - Code areas that require special attention

4. **Mitigation Recommendations**:
   - Immediate security measures
   - Long-term security improvements
   - Testing strategies

Please be specific and technical in your analysis.""",

                'prompt_code_focus': f"""As a code security specialist, analyze this glibc library file:

File: {row['FilePath']}

Based on the file name and location, identify:

1. **Function/Module Purpose**: What does this file likely implement?
2. **Security-Critical Areas**: What operations could be vulnerable?
3. **Common Attack Patterns**: What vulnerabilities typically affect this type of code?
4. **Input Validation**: What inputs should be carefully validated?
5. **Memory Safety**: What memory-related issues could occur?
6. **Concurrency Issues**: Are there potential race conditions?

Provide specific, actionable security insights."""
            }
            
            prompts.append(prompt_data)
        
        return prompts
    
    def save_test_data(self, prompts):
        """Save test data and prompts"""
        print("\n💾 Saving test data...")
        
        # Create directories
        Path("prompts").mkdir(exist_ok=True)
        Path("results").mkdir(exist_ok=True)
        
        # Save prompts
        with open('prompts/test_prompts.json', 'w', encoding='utf-8') as f:
            json.dump(prompts, f, indent=2, ensure_ascii=False)
        
        # Save test samples
        self.test_samples.to_csv('prompts/test_samples.csv', index=False)
        
        # Create summary
        summary = {
            'total_samples': len(self.test_samples),
            'vulnerability_types': self.test_samples['V_CLASSIFICATION'].value_counts().to_dict(),
            'file_types': self.test_samples['FilePath'].apply(lambda x: x.split('/')[-1].split('.')[-1] if '.' in x else 'unknown').value_counts().to_dict(),
            'unique_cves': self.test_samples['CVE'].nunique(),
            'prompt_variants': 3  # basic, detailed, code_focus
        }
        
        with open('prompts/test_summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"✅ Saved {len(prompts)} prompts to prompts/test_prompts.json")
        print(f"✅ Saved test samples to prompts/test_samples.csv")
        print(f"✅ Saved summary to prompts/test_summary.json")

def main():
    print("🚀 Starting glibc vulnerability test data preparation...")
    
    processor = GlibcDataProcessor()
    
    # Load and analyze dataset
    df = processor.load_dataset()
    
    # Create test samples
    test_samples = processor.create_test_samples(n_samples=25)
    
    # Create prompts
    prompts = processor.create_vulnerability_prompts()
    
    # Save everything
    processor.save_test_data(prompts)
    
    print("\n🎉 Data preparation completed successfully!")
    print("\n📋 Next steps:")
    print("   1. Review the generated prompts in prompts/test_prompts.json")
    print("   2. Run test_vulnerability_detection.py to start testing")
    print("   3. Monitor results in the results/ directory")

if __name__ == "__main__":
    main()
