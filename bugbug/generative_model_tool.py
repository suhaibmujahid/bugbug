# -*- coding: utf-8 -*-
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import inspect
import re
from abc import ABC, abstractmethod
from logging import INFO, basicConfig, getLogger
from typing import Any

from bugbug.utils import get_secret

basicConfig(level=INFO)
logger = getLogger(__name__)


def create_human_llm():
    from langchain_community.llms import HumanInputLLM

    return HumanInputLLM()


def create_openai_llm(temperature=0.2):
    from langchain_openai import ChatOpenAI

    return ChatOpenAI(
        model_name="gpt-4o-2024-05-13",
        api_key=get_secret("OPENAI_API_KEY"),
        temperature=temperature,
    )


def create_azureopenai_llm(temperature=0.2):
    from langchain_openai import AzureChatOpenAI

    return AzureChatOpenAI(
        azure_endpoint=get_secret("OPENAI_API_ENDPOINT"),
        azure_deployment=get_secret("OPENAI_API_DEPLOY"),
        api_key=get_secret("OPENAI_API_KEY"),
        api_version=get_secret("OPENAI_API_VERSION"),
        temperature=temperature,
    )


def create_anthropic_llm(temperature=0.2):
    from langchain_anthropic import ChatAnthropic

    return ChatAnthropic(
        model_name="claude-3-5-sonnet-20240620",
        api_key=get_secret("ANTHROPIC_API_KEY"),
        temperature=temperature,
    )


def create_mistral_llm(temperature=0.2):
    from langchain_mistralai import ChatMistralAI

    return ChatMistralAI(
        model_name="mistral-large-latest",
        api_key=get_secret("MISTRAL_API_KEY"),
        temperature=temperature,
    )


AVAILABLE_LLMS = {}

for name in list(globals()):
    match = re.search(r"create_(.*?)_llm", name)
    if match is None:
        continue

    llm_name = match.group(1)
    create_llm_function = globals()[f"create_{llm_name}_llm"]
    AVAILABLE_LLMS[llm_name] = inspect.signature(create_llm_function).parameters


def create_llm_to_args(parser):
    parser.add_argument(
        "--llm",
        help="LLM",
        required=True,
        choices=AVAILABLE_LLMS.keys(),
    )
    for llm_name, llm_arguments in AVAILABLE_LLMS.items():
        group = parser.add_argument_group(f"Options for '{llm_name}' LLM")
        for llm_argument in llm_arguments.values():
            group.add_argument(
                f"--{llm_name}-{llm_argument.name}",
                default=llm_argument.default
                if llm_argument.default is not llm_argument.empty
                else None,
                help=llm_argument.name,
            )


def create_llm_from_args(args):
    if args.llm not in AVAILABLE_LLMS:
        raise NotImplementedError

    llm_creation_args = {}
    for arg_name, arg_value in vars(args).items():
        if arg_name.startswith(f"{args.llm}_"):
            llm_creation_args[arg_name[len(f"{args.llm}_") :]] = arg_value
    return globals()[f"create_{args.llm}_llm"](**llm_creation_args)


class GenerativeModelTool(ABC):
    @property
    @abstractmethod
    def version(self) -> str:
        ...

    def __init__(self, llm, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.llm = llm
        self._set_tokenizer(llm.model_name if hasattr(llm, "model_name") else "")

    def _set_tokenizer(self, model_name: str) -> None:
        import tiktoken

        try:
            self._tokenizer = tiktoken.encoding_for_model(model_name)
        except KeyError:
            FALLBACK_ENCODING = "cl100k_base"
            logger.info(
                "Tokenizer couldn't be found for %s, falling back to %s",
                model_name,
                FALLBACK_ENCODING,
            )
            self._tokenizer = tiktoken.get_encoding(FALLBACK_ENCODING)

    def count_tokens(self, text):
        return len(self._tokenizer.encode(text))

    @abstractmethod
    def run(self, *args, **kwargs) -> Any:
        ...
